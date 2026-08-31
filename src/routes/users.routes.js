import { Router } from 'express';
import { db } from '../lib/db.js';
import { audit } from '../lib/audit.js';
import { requireAuth, sessionPayload } from '../middleware/auth.js';
import * as users from '../services/users.service.js';
import { pageParams, str } from '../lib/validate.js';

export const usersRouter = Router();
usersRouter.use(requireAuth);

/** People this member can share with. */
usersRouter.get('/directory', (req, res) => {
  const q = str(req.query.q, 'Search', { required: false, min: 0, max: 100 });
  res.json({ users: users.listDirectory({ excludeUserId: req.currentUser.id, q }) });
});

usersRouter.get('/me', (req, res) => {
  res.json({
    ...sessionPayload(req),
    backupCodesRemaining: req.currentUser.mfa_enabled === 1 ? users.countUnusedBackupCodes(req.currentUser.id) : 0,
  });
});

usersRouter.patch('/me', (req, res) => {
  const displayName = str(req.body?.displayName, 'Name', { min: 2, max: 80 });
  users.updateProfile(req.currentUser.id, { displayName });
  audit({ req, action: 'account.update', outcome: 'success', objectType: 'user', objectId: req.currentUser.public_id, targetUserId: req.currentUser.id, details: { displayName } });
  res.json({ user: users.publicUser(users.findById(req.currentUser.id)) });
});

/** A member's own audit trail - the same records the administrator sees, scoped to them. */
usersRouter.get('/me/activity', (req, res) => {
  const { limit, offset } = pageParams(req.query, { defaultLimit: 100 });
  const entries = db
    .prepare(
      `SELECT id, ts, action, outcome, object_type, object_id, object_label, ip, details
         FROM audit_log
        WHERE actor_id = ? OR target_user_id = ?
        ORDER BY id DESC LIMIT ? OFFSET ?`,
    )
    .all(req.currentUser.id, req.currentUser.id, limit, offset)
    .map((e) => ({ ...e, details: JSON.parse(e.details) }));
  const total = db
    .prepare('SELECT COUNT(*) AS n FROM audit_log WHERE actor_id = ? OR target_user_id = ?')
    .get(req.currentUser.id, req.currentUser.id).n;
  res.json({ entries, total, limit, offset });
});
