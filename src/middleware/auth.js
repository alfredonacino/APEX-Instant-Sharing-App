import { config } from '../config.js';
import { audit } from '../lib/audit.js';
import { findById, publicUser, isLocked } from '../services/users.service.js';
import { HttpError, forbidden, unauthorized } from '../lib/validate.js';

export const STAGE = {
  MFA_SETUP: 'mfa_setup',       // password accepted, enrolment still required
  MFA_REQUIRED: 'mfa_required', // password accepted, waiting for the 6-digit code
  AUTHENTICATED: 'authenticated',
};

/**
 * Resolves the session into req.currentUser and enforces the absolute session
 * lifetime plus account status. Runs on every request; sets nothing when the
 * caller is anonymous.
 */
export function loadUser(req, res, next) {
  const { userId, stage, startedAt } = req.session ?? {};
  if (!userId) return next();

  if (startedAt && Date.now() - startedAt > config.sessionAbsoluteMs) {
    const email = req.session.email;
    return req.session.destroy(() => {
      audit({ req, action: 'auth.session.expired', outcome: 'success', details: { email, reason: 'absolute_timeout' } });
      res.status(401).json({ error: 'Session expired, please sign in again', code: 'session_expired' });
    });
  }

  const row = findById(userId);
  if (!row || row.status !== 'active') {
    return req.session.destroy(() => {
      res.status(401).json({ error: 'Account is not available', code: 'account_unavailable' });
    });
  }

  req.currentUser = row;
  req.authStage = stage ?? STAGE.MFA_REQUIRED;
  return next();
}

export function requireAuth(req, res, next) {
  if (!req.currentUser) return next(unauthorized());
  if (req.authStage !== STAGE.AUTHENTICATED) {
    const code = req.authStage === STAGE.MFA_SETUP ? 'mfa_setup_required' : 'mfa_required';
    return next(new HttpError(401, 'Multi-factor authentication is not complete', { code }));
  }
  if (isLocked(req.currentUser)) return next(forbidden('Account is temporarily locked'));
  return next();
}

/** For the MFA endpoints themselves: a half-authenticated session is expected. */
export function requireStage(...stages) {
  return (req, res, next) => {
    if (!req.currentUser) return next(unauthorized());
    if (!stages.includes(req.authStage)) return next(forbidden('Not valid at this point in sign-in'));
    return next();
  };
}

export function requireAdmin(req, res, next) {
  if (!req.currentUser) return next(unauthorized());
  if (req.currentUser.role !== 'admin') {
    audit({ req, action: 'admin.audit.view', outcome: 'denied', details: { path: req.originalUrl } });
    return next(forbidden('Administrator access required'));
  }
  return next();
}

/** Everything the browser needs to render the right screen. */
export function sessionPayload(req) {
  if (!req.currentUser) {
    return { authenticated: false, stage: null, user: null, policy: publicPolicy() };
  }
  return {
    authenticated: req.authStage === STAGE.AUTHENTICATED,
    stage: req.authStage,
    user: publicUser(req.currentUser),
    policy: publicPolicy(),
  };
}

export function publicPolicy() {
  return {
    appName: config.appName,
    requireMfa: config.requireMfa,
    allowSelfRegistration: config.allowSelfRegistration,
    maxUploadBytes: config.maxUploadBytes,
    maxFilesPerUpload: config.maxFilesPerUpload,
    passwordMinLength: config.passwordMinLength,
    adminCanDownloadAll: config.adminCanDownloadAll,
  };
}
