import { Router } from 'express';
import { db } from '../lib/db.js';
import { config } from '../config.js';
import { audit, verifyAuditChain, AUDIT_ACTIONS } from '../lib/audit.js';
import { sessionStore } from '../lib/session-store.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import * as users from '../services/users.service.js';
import { storageStats } from '../services/files.service.js';
import {
  badRequest, conflict, email as parseEmail, oneOf, pageParams,
  password as parsePassword, str,
} from '../lib/validate.js';

export const adminRouter = Router();
adminRouter.use(requireAuth, requireAdmin);

adminRouter.get('/stats', (req, res) => {
  const chain = verifyAuditChain();
  res.json({
    storage: storageStats(),
    audit: { entries: chain.entries, intact: chain.ok },
    policy: {
      requireMfa: config.requireMfa,
      allowSelfRegistration: config.allowSelfRegistration,
      adminCanDownloadAll: config.adminCanDownloadAll,
      maxUploadBytes: config.maxUploadBytes,
      sessionIdleMinutes: config.sessionIdleMs / 60000,
      sessionAbsoluteHours: config.sessionAbsoluteMs / 3600000,
      lockoutAfter: config.maxFailedLogins,
    },
  });
});

// ------------------------------------------------------------------ users --

adminRouter.get('/users', (req, res) => {
  const { limit, offset } = pageParams(req.query, { defaultLimit: 100 });
  const q = str(req.query.q, 'Search', { required: false, min: 0, max: 100 });
  res.json({ ...users.listAllUsers({ q, limit, offset }), limit, offset });
});

/** Create an account directly - the route used when self-registration is off. */
adminRouter.post('/users', async (req, res) => {
  const email = parseEmail(req.body?.email);
  const displayName = str(req.body?.displayName, 'Name', { min: 2, max: 80 });
  const password = parsePassword(req.body?.password, { minLength: config.passwordMinLength });
  const role = oneOf(req.body?.role || 'user', ['user', 'admin'], 'Role');

  const created = await users.createUser({ email, displayName, password, role });
  audit({
    req, action: 'admin.user.update', outcome: 'success', objectType: 'user',
    objectId: created.public_id, targetUserId: created.id,
    details: { operation: 'create', email, role, mfaPending: true },
  });
  res.status(201).json({ user: users.publicUser(created) });
});

adminRouter.patch('/users/:id', (req, res) => {
  const target = users.requireByPublicId(req.params.id);
  const role = req.body?.role === undefined ? undefined : oneOf(req.body.role, ['user', 'admin'], 'Role');
  const status = req.body?.status === undefined ? undefined : oneOf(req.body.status, ['active', 'disabled'], 'Status');
  if (role === undefined && status === undefined) throw badRequest('Nothing to update');

  // Never allow the last active administrator to be removed or locked out.
  const losingAdmin = (role === 'user' && target.role === 'admin') || (status === 'disabled' && target.role === 'admin');
  if (losingAdmin && users.countAdmins({ excludeUserId: target.id }) === 0) {
    throw conflict('This is the last active administrator - promote someone else first');
  }
  if (target.id === req.currentUser.id && status === 'disabled') throw conflict('You cannot disable your own account');

  const updated = users.setRoleAndStatus(target.id, { role, status });
  if (status === 'disabled') sessionStore.destroyByUser(target.id);

  audit({
    req, action: 'admin.user.update', outcome: 'success', objectType: 'user',
    objectId: target.public_id, targetUserId: target.id,
    details: {
      operation: 'update',
      role: role ? { from: target.role, to: role } : undefined,
      status: status ? { from: target.status, to: status } : undefined,
      sessionsRevoked: status === 'disabled',
    },
  });
  res.json({ user: users.publicUser(updated) });
});

adminRouter.post('/users/:id/unlock', (req, res) => {
  const target = users.requireByPublicId(req.params.id);
  users.unlock(target.id);
  audit({ req, action: 'account.unlock', outcome: 'success', objectType: 'user', objectId: target.public_id, targetUserId: target.id });
  res.json({ user: users.publicUser(users.findById(target.id)) });
});

/**
 * Clear a lost authenticator. The account keeps its password but must enrol a
 * new device before it can be used again, and every session is revoked.
 */
adminRouter.post('/users/:id/mfa/reset', (req, res) => {
  const target = users.requireByPublicId(req.params.id);
  const reason = str(req.body?.reason, 'Reason', { min: 3, max: 200 });
  users.disableMfa(target.id);
  sessionStore.destroyByUser(target.id);
  audit({
    req, action: 'mfa.reset', outcome: 'success', objectType: 'user',
    objectId: target.public_id, targetUserId: target.id,
    details: { reason, sessionsRevoked: true, reEnrolmentRequired: config.requireMfa },
  });
  res.json({ user: users.publicUser(users.findById(target.id)) });
});

adminRouter.post('/users/:id/password', async (req, res) => {
  const target = users.requireByPublicId(req.params.id);
  const newPassword = parsePassword(req.body?.newPassword, { minLength: config.passwordMinLength });
  const reason = str(req.body?.reason, 'Reason', { min: 3, max: 200 });
  await users.changePassword(target.id, newPassword);
  sessionStore.destroyByUser(target.id);
  audit({
    req, action: 'admin.user.update', outcome: 'success', objectType: 'user',
    objectId: target.public_id, targetUserId: target.id,
    details: { operation: 'password_reset', reason, sessionsRevoked: true },
  });
  res.json({ ok: true });
});

// ------------------------------------------------------------------ audit --

const AUDIT_COLUMNS = `id, ts, actor_id, actor_email, actor_role, action, outcome, object_type,
                       object_id, object_label, target_user_id, ip, user_agent, details`;

function auditQuery(query) {
  const clauses = [];
  const params = {};
  if (query.action) {
    clauses.push('action = :action');
    params.action = String(query.action);
  }
  if (query.outcome) {
    clauses.push('outcome = :outcome');
    params.outcome = oneOf(String(query.outcome), ['success', 'failure', 'denied'], 'Outcome');
  }
  if (query.actor) {
    clauses.push('actor_email LIKE :actor ESCAPE \'\\\'');
    params.actor = `%${String(query.actor).replace(/[%_]/g, (m) => `\\${m}`)}%`;
  }
  if (query.objectId) {
    clauses.push('object_id = :objectId');
    params.objectId = String(query.objectId);
  }
  if (query.from) {
    clauses.push('ts >= :from');
    params.from = new Date(query.from).toISOString();
  }
  if (query.to) {
    clauses.push('ts <= :to');
    params.to = new Date(query.to).toISOString();
  }
  if (query.q) {
    clauses.push('(object_label LIKE :q ESCAPE \'\\\' OR details LIKE :q ESCAPE \'\\\' OR ip LIKE :q ESCAPE \'\\\')');
    params.q = `%${String(query.q).replace(/[%_]/g, (m) => `\\${m}`)}%`;
  }
  return { where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

adminRouter.get('/audit', (req, res) => {
  const { limit, offset } = pageParams(req.query, { defaultLimit: 100, maxLimit: 500 });
  const { where, params } = auditQuery(req.query);

  const entries = db
    .prepare(`SELECT ${AUDIT_COLUMNS} FROM audit_log ${where} ORDER BY id DESC LIMIT :limit OFFSET :offset`)
    .all({ ...params, limit, offset })
    .map((e) => ({ ...e, details: JSON.parse(e.details) }));
  const total = db.prepare(`SELECT COUNT(*) AS n FROM audit_log ${where}`).get(params).n;

  audit({ req, action: 'admin.audit.view', outcome: 'success', details: { filters: { ...req.query }, returned: entries.length } });
  res.json({ entries, total, limit, offset, actions: AUDIT_ACTIONS });
});

/** CSV export for offline retention. */
adminRouter.get('/audit.csv', (req, res) => {
  const { where, params } = auditQuery(req.query);
  const rows = db.prepare(`SELECT ${AUDIT_COLUMNS}, prev_hash, hash FROM audit_log ${where} ORDER BY id ASC`).all(params);

  const escape = (value) => {
    const text = value === null || value === undefined ? '' : String(value);
    return /["\n,]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const header = 'id,ts,actor_email,actor_role,action,outcome,object_type,object_id,object_label,ip,user_agent,details,hash';
  const body = rows
    .map((r) => [r.id, r.ts, r.actor_email, r.actor_role, r.action, r.outcome, r.object_type, r.object_id, r.object_label, r.ip, r.user_agent, r.details, r.hash].map(escape).join(','))
    .join('\n');

  audit({ req, action: 'admin.audit.view', outcome: 'success', details: { export: 'csv', rows: rows.length } });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="audit-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(`${header}\n${body}\n`);
});

/** Recompute the hash chain end to end and report the first divergence. */
adminRouter.get('/audit/verify', (req, res) => {
  const result = verifyAuditChain();
  audit({ req, action: 'admin.audit.verify', outcome: result.ok ? 'success' : 'failure', details: result });
  res.json(result);
});
