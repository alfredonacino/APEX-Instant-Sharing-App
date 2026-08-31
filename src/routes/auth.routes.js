import { Router } from 'express';
import { db, nowIso } from '../lib/db.js';
import { config } from '../config.js';
import { audit } from '../lib/audit.js';
import { sessionStore } from '../lib/session-store.js';
import { newSecret, otpauthUri, qrDataUrl, checkToken } from '../lib/totp.js';
import { encryptSecret, decryptSecret, hashPassword, verifyPassword } from '../lib/crypto.js';
import * as users from '../services/users.service.js';
import { STAGE, requireAuth, requireStage, sessionPayload } from '../middleware/auth.js';
import { loginLimiter, registerLimiter, mfaLimiter } from '../middleware/rate-limit.js';
import { HttpError, badRequest, forbidden, unauthorized, email as parseEmail, password as parsePassword, str, totpToken } from '../lib/validate.js';

export const authRouter = Router();

// A fixed hash so a login attempt for an unknown address costs the same as a
// real one; without it, response time discloses which addresses are registered.
const DUMMY_HASH = await hashPassword(`decoy:${Math.random()}`);

const regenerate = (req) => new Promise((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve())));
const save = (req) => new Promise((resolve, reject) => req.session.save((e) => (e ? reject(e) : resolve())));
const destroy = (req) => new Promise((resolve, reject) => req.session.destroy((e) => (e ? reject(e) : resolve())));

/** Start a fresh session for a user at the given stage (prevents session fixation). */
async function establishSession(req, user, stage) {
  await regenerate(req);
  req.session.userId = user.id;
  req.session.email = user.email;
  req.session.stage = stage;
  req.session.startedAt = Date.now();
  req.currentUser = user;
  req.authStage = stage;
  await save(req);
}

function stageForUser(user) {
  if (user.mfa_enabled === 1) return STAGE.MFA_REQUIRED;
  return config.requireMfa ? STAGE.MFA_SETUP : STAGE.AUTHENTICATED;
}

// ------------------------------------------------------------------ session

authRouter.get('/session', (req, res) => {
  res.json({ ...sessionPayload(req), csrfToken: req.csrfToken });
});

// ----------------------------------------------------------------- register

authRouter.post('/register', registerLimiter, async (req, res) => {
  if (!config.allowSelfRegistration) {
    audit({ req, action: 'auth.register', outcome: 'denied', details: { email: req.body?.email, reason: 'self_registration_disabled' } });
    throw forbidden('Self-registration is disabled - ask an administrator for an account');
  }

  const email = parseEmail(req.body?.email);
  const displayName = str(req.body?.displayName, 'Name', { min: 2, max: 80 });
  const password = parsePassword(req.body?.password, { minLength: config.passwordMinLength });

  // The very first account becomes the administrator, so a fresh deployment is usable.
  const isFirstAccount = users.countUsers() === 0;
  const user = await users.createUser({
    email,
    displayName,
    password,
    role: isFirstAccount ? 'admin' : 'user',
  });

  audit({
    req,
    actor: { id: user.id, email: user.email, role: user.role },
    action: 'auth.register',
    outcome: 'success',
    objectType: 'user',
    objectId: user.public_id,
    targetUserId: user.id,
    details: { displayName, firstAccount: isFirstAccount, role: user.role },
  });

  await establishSession(req, user, stageForUser(user));
  res.status(201).json({ ...sessionPayload(req), firstAccount: isFirstAccount });
});

// -------------------------------------------------------------------- login

authRouter.post('/login', loginLimiter, async (req, res) => {
  const email = parseEmail(req.body?.email);
  const password = str(req.body?.password, 'Password', { min: 1, max: 1024, trim: false });
  const user = users.findByEmail(email);

  if (!user) {
    await verifyPassword(password, DUMMY_HASH);
    audit({ req, action: 'auth.login', outcome: 'failure', details: { email, reason: 'unknown_account' } });
    throw unauthorized('Email address or password is incorrect');
  }
  if (user.status !== 'active') {
    audit({ req, action: 'auth.login', outcome: 'denied', targetUserId: user.id, details: { email, reason: 'account_disabled' } });
    throw forbidden('This account has been disabled');
  }
  if (users.isLocked(user)) {
    audit({ req, action: 'auth.login', outcome: 'denied', targetUserId: user.id, details: { email, reason: 'locked', until: user.locked_until } });
    throw new HttpError(423, 'Too many failed attempts - this account is temporarily locked', { code: 'locked', details: { until: user.locked_until } });
  }

  if (!(await users.checkPassword(user, password))) {
    const locked = users.registerFailedLogin(user.id);
    audit({ req, action: 'auth.login', outcome: 'failure', targetUserId: user.id, details: { email, reason: 'bad_password', lockedNow: locked } });
    if (locked) {
      audit({ req, action: 'account.lock', outcome: 'success', objectType: 'user', objectId: user.public_id, targetUserId: user.id, details: { minutes: config.lockoutMs / 60000 } });
      throw new HttpError(423, 'Too many failed attempts - this account is temporarily locked', { code: 'locked' });
    }
    throw unauthorized('Email address or password is incorrect');
  }

  users.clearFailedLogins(user.id);
  const stage = stageForUser(user);
  if (stage === STAGE.AUTHENTICATED) users.clearFailedLogins(user.id, { markLogin: true });

  audit({
    req,
    actor: user,
    action: 'auth.login',
    outcome: 'success',
    targetUserId: user.id,
    details: { email, stage, mfa: user.mfa_enabled === 1 },
  });

  await establishSession(req, users.findById(user.id), stage);
  res.json(sessionPayload(req));
});

// -------------------------------------------------------------------- MFA --

/** Begin (or restart) TOTP enrolment. Re-enrolment requires the password again. */
authRouter.post('/mfa/setup', mfaLimiter, requireStage(STAGE.MFA_SETUP, STAGE.AUTHENTICATED), async (req, res) => {
  const user = req.currentUser;

  if (user.mfa_enabled === 1) {
    const password = str(req.body?.password, 'Password', { min: 1, max: 1024, trim: false });
    if (!(await users.checkPassword(user, password))) {
      audit({ req, action: 'mfa.setup.start', outcome: 'failure', targetUserId: user.id, details: { reason: 'bad_password' } });
      throw unauthorized('Password is incorrect');
    }
  }

  const secret = newSecret();
  req.session.pendingMfaSecret = encryptSecret(secret);
  req.session.pendingMfaStartedAt = Date.now();
  await save(req);

  const uri = otpauthUri(secret, user.email);
  audit({ req, actor: user, action: 'mfa.setup.start', outcome: 'success', targetUserId: user.id });

  res.json({
    secret,                       // shown so the user can type it in manually
    otpauthUri: uri,
    qrDataUrl: await qrDataUrl(uri),
    issuer: config.appName,
    account: user.email,
  });
});

/** Confirm enrolment with a live code, then issue single-use backup codes. */
authRouter.post('/mfa/enable', mfaLimiter, requireStage(STAGE.MFA_SETUP, STAGE.AUTHENTICATED), async (req, res) => {
  const user = req.currentUser;
  const token = totpToken(req.body?.token);
  const pending = req.session.pendingMfaSecret;
  if (!pending) throw badRequest('Start the enrolment again - no pending setup was found');
  if (Date.now() - (req.session.pendingMfaStartedAt ?? 0) > 15 * 60_000) {
    throw badRequest('Enrolment timed out - start again');
  }

  const secret = decryptSecret(pending);
  const { valid, step } = await checkToken(secret, token);
  if (!valid) {
    audit({ req, actor: user, action: 'mfa.enable', outcome: 'failure', targetUserId: user.id, details: { reason: 'bad_code' } });
    throw unauthorized('That code is not valid - check the clock on your device and try the next code');
  }

  const backupCodes = users.enableMfa(user.id, secret);
  db.prepare('UPDATE users SET mfa_last_step = ? WHERE id = ?').run(step, user.id);
  users.clearFailedLogins(user.id, { markLogin: true });

  delete req.session.pendingMfaSecret;
  delete req.session.pendingMfaStartedAt;
  req.session.stage = STAGE.AUTHENTICATED;
  req.authStage = STAGE.AUTHENTICATED;
  req.currentUser = users.findById(user.id);
  await save(req);

  audit({ req, actor: req.currentUser, action: 'mfa.enable', outcome: 'success', targetUserId: user.id, details: { backupCodes: backupCodes.length } });
  res.json({ ...sessionPayload(req), backupCodes });
});

/** Second factor at sign-in: a TOTP code, or one backup code. */
authRouter.post('/mfa/verify', mfaLimiter, requireStage(STAGE.MFA_REQUIRED), async (req, res) => {
  const user = req.currentUser;
  const usingBackup = Boolean(req.body?.backupCode);

  if (usingBackup) {
    const code = str(req.body.backupCode, 'Backup code', { min: 8, max: 32 });
    if (!users.consumeBackupCode(user.id, code)) {
      const locked = users.registerFailedLogin(user.id);
      audit({ req, actor: user, action: 'auth.login.backup_code', outcome: 'failure', targetUserId: user.id, details: { lockedNow: locked } });
      throw unauthorized('That backup code is not valid or has already been used');
    }
    const remaining = users.countUnusedBackupCodes(user.id);
    users.clearFailedLogins(user.id, { markLogin: true });
    req.session.stage = STAGE.AUTHENTICATED;
    req.authStage = STAGE.AUTHENTICATED;
    req.currentUser = users.findById(user.id);
    await save(req);
    audit({ req, actor: req.currentUser, action: 'auth.login.backup_code', outcome: 'success', targetUserId: user.id, details: { remaining } });
    return res.json({ ...sessionPayload(req), backupCodesRemaining: remaining });
  }

  const token = totpToken(req.body?.token);
  const secret = users.getTotpSecret(user);
  if (!secret) throw badRequest('This account has no authenticator enrolled');

  const { valid, step } = await checkToken(secret, token);
  // A code stays valid for its whole 30-second step; refuse one already used.
  const replayed = valid && user.mfa_last_step !== null && step !== null && step <= user.mfa_last_step;

  if (!valid || replayed) {
    const locked = users.registerFailedLogin(user.id);
    audit({
      req, actor: user, action: 'auth.login.mfa', outcome: 'failure', targetUserId: user.id,
      details: { reason: replayed ? 'replayed_code' : 'bad_code', lockedNow: locked },
    });
    if (locked) {
      audit({ req, action: 'account.lock', outcome: 'success', objectType: 'user', objectId: user.public_id, targetUserId: user.id, details: { trigger: 'mfa' } });
      throw new HttpError(423, 'Too many failed attempts - this account is temporarily locked', { code: 'locked' });
    }
    throw unauthorized(replayed ? 'That code has already been used - wait for the next one' : 'That code is not valid');
  }

  db.prepare('UPDATE users SET mfa_last_step = ? WHERE id = ?').run(step, user.id);
  users.clearFailedLogins(user.id, { markLogin: true });
  req.session.stage = STAGE.AUTHENTICATED;
  req.authStage = STAGE.AUTHENTICATED;
  req.currentUser = users.findById(user.id);
  await save(req);

  audit({ req, actor: req.currentUser, action: 'auth.login.mfa', outcome: 'success', targetUserId: user.id });
  return res.json(sessionPayload(req));
});

/** Issue a new set of backup codes; the old set stops working immediately. */
authRouter.post('/mfa/backup-codes', mfaLimiter, requireAuth, async (req, res) => {
  const user = req.currentUser;
  if (user.mfa_enabled !== 1) throw badRequest('Enrol an authenticator first');
  const password = str(req.body?.password, 'Password', { min: 1, max: 1024, trim: false });
  if (!(await users.checkPassword(user, password))) throw unauthorized('Password is incorrect');
  const token = totpToken(req.body?.token);
  const { valid } = await checkToken(users.getTotpSecret(user), token);
  if (!valid) throw unauthorized('That code is not valid');

  const codes = users.replaceBackupCodes(user.id);
  audit({ req, action: 'mfa.backup_codes.regenerate', outcome: 'success', targetUserId: user.id, details: { count: codes.length } });
  res.json({ backupCodes: codes });
});

/** Only possible when the deployment does not mandate MFA. */
authRouter.post('/mfa/disable', mfaLimiter, requireAuth, async (req, res) => {
  if (config.requireMfa) throw forbidden('Multi-factor authentication is mandatory on this deployment');
  const user = req.currentUser;
  const password = str(req.body?.password, 'Password', { min: 1, max: 1024, trim: false });
  if (!(await users.checkPassword(user, password))) throw unauthorized('Password is incorrect');
  const token = totpToken(req.body?.token);
  const { valid } = await checkToken(users.getTotpSecret(user), token);
  if (!valid) throw unauthorized('That code is not valid');

  users.disableMfa(user.id);
  audit({ req, action: 'mfa.disable', outcome: 'success', targetUserId: user.id });
  res.json({ ok: true });
});

// ----------------------------------------------------------------- account --

authRouter.post('/password', requireAuth, async (req, res) => {
  const user = req.currentUser;
  const current = str(req.body?.currentPassword, 'Current password', { min: 1, max: 1024, trim: false });
  const next = parsePassword(req.body?.newPassword, { minLength: config.passwordMinLength });

  if (!(await users.checkPassword(user, current))) {
    audit({ req, action: 'auth.password.change', outcome: 'failure', targetUserId: user.id, details: { reason: 'bad_password' } });
    throw unauthorized('Current password is incorrect');
  }
  if (user.mfa_enabled === 1) {
    const { valid } = await checkToken(users.getTotpSecret(user), totpToken(req.body?.token));
    if (!valid) throw unauthorized('That code is not valid');
  }

  await users.changePassword(user.id, next);

  // Sign every other device out, then re-establish this one.
  sessionStore.destroyByUser(user.id);
  await establishSession(req, users.findById(user.id), STAGE.AUTHENTICATED);

  audit({ req, action: 'auth.password.change', outcome: 'success', targetUserId: user.id, details: { otherSessionsRevoked: true } });
  res.json({ ok: true, ...sessionPayload(req) });
});

authRouter.post('/logout', async (req, res) => {
  const user = req.currentUser;
  if (user) audit({ req, actor: user, action: 'auth.logout', outcome: 'success', targetUserId: user.id });
  if (req.session) await destroy(req);
  res.clearCookie('apex.sid');
  res.json({ ok: true });
});
