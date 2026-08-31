import { db, nowIso, transaction } from '../lib/db.js';
import { config } from '../config.js';
import {
  hashPassword, verifyPassword, encryptSecret, decryptSecret, keyedHash,
  publicId, generateBackupCode, normalizeBackupCode,
} from '../lib/crypto.js';
import { conflict, notFound } from '../lib/validate.js';

const SELECT = `SELECT * FROM users`;

/** Shape sent to the browser. Never includes password_hash or mfa_secret. */
export function publicUser(row) {
  if (!row) return null;
  return {
    id: row.public_id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    status: row.status,
    mfaEnabled: row.mfa_enabled === 1,
    mfaEnrolledAt: row.mfa_enrolled_at,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
    locked: isLocked(row),
    lockedUntil: row.locked_until,
  };
}

export const findByEmail = (email) => db.prepare(`${SELECT} WHERE email = ?`).get(String(email).toLowerCase()) ?? null;
export const findById = (id) => db.prepare(`${SELECT} WHERE id = ?`).get(id) ?? null;
export const findByPublicId = (pid) => db.prepare(`${SELECT} WHERE public_id = ?`).get(String(pid)) ?? null;

export function requireByPublicId(pid) {
  const user = findByPublicId(pid);
  if (!user) throw notFound('User not found');
  return user;
}

export function countUsers() {
  return db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
}

export async function createUser({ email, displayName, password, role = 'user', status = 'active' }) {
  if (findByEmail(email)) throw conflict('An account with that email address already exists');
  const passwordHash = await hashPassword(password);
  const ts = nowIso();
  try {
    db.prepare(
      `INSERT INTO users (public_id, email, display_name, password_hash, role, status,
                          password_changed_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(publicId('usr'), String(email).toLowerCase(), displayName, passwordHash, role, status, ts, ts, ts);
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) throw conflict('An account with that email address already exists');
    throw error;
  }
  return findByEmail(email);
}

/** Directory used by the share picker: active accounts other than the viewer. */
export function listDirectory({ excludeUserId = null, q = '', limit = 100 } = {}) {
  const like = `%${String(q).replace(/[%_]/g, (m) => `\\${m}`)}%`;
  return db
    .prepare(
      `SELECT * FROM users
        WHERE status = 'active' AND id IS NOT ?
          AND (? = '' OR display_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')
        ORDER BY display_name COLLATE NOCASE ASC LIMIT ?`,
    )
    .all(excludeUserId, String(q), like, like, limit)
    .map(publicUser);
}

export function listAllUsers({ q = '', limit = 200, offset = 0 } = {}) {
  const like = `%${String(q).replace(/[%_]/g, (m) => `\\${m}`)}%`;
  const rows = db
    .prepare(
      `SELECT * FROM users
        WHERE (? = '' OR display_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')
        ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    )
    .all(String(q), like, like, limit, offset);
  const total = db
    .prepare(`SELECT COUNT(*) AS n FROM users WHERE (? = '' OR display_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')`)
    .get(String(q), like, like).n;
  return { users: rows.map(publicUser), total };
}

export function touchUpdated(userId) {
  db.prepare('UPDATE users SET updated_at = ? WHERE id = ?').run(nowIso(), userId);
}

// --------------------------------------------------------------- lockout ---

export function isLocked(row) {
  return Boolean(row?.locked_until && new Date(row.locked_until).getTime() > Date.now());
}

/** Returns true when this failure pushed the account into a lockout. */
export function registerFailedLogin(userId) {
  const row = findById(userId);
  if (!row) return false;
  const count = row.failed_login_count + 1;
  const lock = count >= config.maxFailedLogins;
  db.prepare('UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?').run(
    lock ? 0 : count,
    lock ? new Date(Date.now() + config.lockoutMs).toISOString() : row.locked_until,
    nowIso(),
    userId,
  );
  return lock;
}

export function clearFailedLogins(userId, { markLogin = false } = {}) {
  const ts = nowIso();
  db.prepare(
    `UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ?
        ${markLogin ? ', last_login_at = ?' : ''} WHERE id = ?`,
  ).run(...(markLogin ? [ts, ts, userId] : [ts, userId]));
}

export function unlock(userId) {
  db.prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?').run(nowIso(), userId);
}

// ------------------------------------------------------------------- MFA ---

export function getTotpSecret(row) {
  return row.mfa_secret ? decryptSecret(row.mfa_secret) : null;
}

/** Enable TOTP and issue a fresh set of single-use backup codes. */
export const enableMfa = transaction((userId, secretPlain) => {
  const ts = nowIso();
  db.prepare('UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_enrolled_at = ?, updated_at = ? WHERE id = ?').run(
    encryptSecret(secretPlain), ts, ts, userId,
  );
  return replaceBackupCodes(userId);
});

export function replaceBackupCodes(userId, count = 10) {
  db.prepare('DELETE FROM mfa_backup_codes WHERE user_id = ?').run(userId);
  const insert = db.prepare('INSERT INTO mfa_backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)');
  const ts = nowIso();
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    const code = generateBackupCode();
    codes.push(code);
    insert.run(userId, keyedHash(normalizeBackupCode(code)), ts);
  }
  return codes;
}

export function countUnusedBackupCodes(userId) {
  return db.prepare('SELECT COUNT(*) AS n FROM mfa_backup_codes WHERE user_id = ? AND used_at IS NULL').get(userId).n;
}

/** Consume a backup code. Returns true when a matching unused code was burned. */
export const consumeBackupCode = transaction((userId, rawCode) => {
  const hash = keyedHash(normalizeBackupCode(rawCode));
  const row = db
    .prepare('SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
    .get(userId, hash);
  if (!row) return false;
  db.prepare('UPDATE mfa_backup_codes SET used_at = ? WHERE id = ?').run(nowIso(), row.id);
  return true;
});

export const disableMfa = transaction((userId) => {
  db.prepare('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_enrolled_at = NULL, updated_at = ? WHERE id = ?')
    .run(nowIso(), userId);
  db.prepare('DELETE FROM mfa_backup_codes WHERE user_id = ?').run(userId);
});

// -------------------------------------------------------------- profile ----

export async function changePassword(userId, newPassword) {
  const ts = nowIso();
  db.prepare('UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?').run(
    await hashPassword(newPassword), ts, ts, userId,
  );
}

export async function checkPassword(row, candidate) {
  return verifyPassword(candidate, row.password_hash);
}

export function updateProfile(userId, { displayName }) {
  db.prepare('UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?').run(displayName, nowIso(), userId);
}

export function setRoleAndStatus(userId, { role, status }) {
  const current = findById(userId);
  if (!current) throw notFound('User not found');
  db.prepare('UPDATE users SET role = ?, status = ?, updated_at = ? WHERE id = ?').run(
    role ?? current.role, status ?? current.status, nowIso(), userId,
  );
  return findById(userId);
}

export function countAdmins({ excludeUserId = null } = {}) {
  return db
    .prepare(`SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active' AND id IS NOT ?`)
    .get(excludeUserId).n;
}
