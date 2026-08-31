import crypto from 'node:crypto';
import { db, nowIso } from './db.js';
import { config } from '../config.js';

const GENESIS = 'genesis';

/** Every action the application records. Kept in one place so the admin UI can offer a filter list. */
export const AUDIT_ACTIONS = [
  'auth.register',
  'auth.login',
  'auth.login.mfa',
  'auth.login.backup_code',
  'auth.logout',
  'auth.password.change',
  'auth.session.expired',
  'mfa.setup.start',
  'mfa.enable',
  'mfa.disable',
  'mfa.backup_codes.regenerate',
  'mfa.reset',
  'account.lock',
  'account.unlock',
  'account.update',
  'file.upload',
  'file.download',
  'file.update',
  'file.delete',
  'file.list',
  'share.grant',
  'share.revoke',
  'share.visibility',
  'admin.user.update',
  'admin.audit.view',
  'admin.audit.verify',
  'security.csrf_rejected',
  'security.rate_limited',
];

const insertStmt = db.prepare(`
  INSERT INTO audit_log (ts, actor_id, actor_email, actor_role, action, outcome, object_type,
                         object_id, object_label, target_user_id, ip, user_agent, details, prev_hash, hash)
  VALUES (:ts, :actor_id, :actor_email, :actor_role, :action, :outcome, :object_type,
          :object_id, :object_label, :target_user_id, :ip, :user_agent, :details, :prev_hash, :hash)
`);

const lastHashStmt = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1');

/** Canonical serialisation of the fields the chain commits to. */
function digest(prevHash, row) {
  const canonical = JSON.stringify([
    row.ts, row.actor_id, row.actor_email, row.actor_role, row.action, row.outcome,
    row.object_type, row.object_id, row.object_label, row.target_user_id,
    row.ip, row.user_agent, row.details,
  ]);
  return crypto.createHmac('sha256', config.appKey).update(`${prevHash}\n${canonical}`).digest('hex');
}

function clientIp(req) {
  if (!req) return null;
  const ip = req.ip || req.socket?.remoteAddress || null;
  return ip ? String(ip).replace(/^::ffff:/, '') : null;
}

/**
 * Append one entry to the audit trail.
 *
 * Auditing must never break the operation being audited, so failures here are
 * logged to stderr rather than thrown - except for the append-only triggers,
 * which indicate tampering and are worth surfacing loudly.
 */
export function audit({
  req = null,
  actor = null,
  action,
  outcome = 'success',
  objectType = null,
  objectId = null,
  objectLabel = null,
  targetUserId = null,
  details = {},
} = {}) {
  const actorFromSession = actor ?? req?.currentUser ?? null;
  const row = {
    ts: nowIso(),
    actor_id: actorFromSession?.id ?? null,
    actor_email: actorFromSession?.email ?? details.email ?? null,
    actor_role: actorFromSession?.role ?? null,
    action,
    outcome,
    object_type: objectType,
    object_id: objectId === null || objectId === undefined ? null : String(objectId),
    object_label: objectLabel,
    target_user_id: targetUserId,
    ip: clientIp(req),
    user_agent: req?.get?.('user-agent')?.slice(0, 300) ?? null,
    details: JSON.stringify(details ?? {}),
  };

  const write = () => {
    const prev = lastHashStmt.get()?.hash ?? GENESIS;
    insertStmt.run({ ...row, prev_hash: prev, hash: digest(prev, row) });
  };

  try {
    // Reading the previous hash and inserting must be atomic, but the caller
    // may already own a transaction.
    if (db.isTransaction) {
      write();
    } else {
      db.exec('BEGIN IMMEDIATE');
      try {
        write();
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    }
  } catch (error) {
    console.error('[audit] failed to record entry', { action, outcome }, error);
  }
}

/**
 * Recompute the chain from the beginning.
 * Returns the first divergence, if any, plus the number of entries checked.
 */
export function verifyAuditChain() {
  const rows = db
    .prepare(
      `SELECT id, ts, actor_id, actor_email, actor_role, action, outcome, object_type, object_id,
              object_label, target_user_id, ip, user_agent, details, prev_hash, hash
       FROM audit_log ORDER BY id ASC`,
    )
    .all();

  let prev = GENESIS;
  for (const row of rows) {
    if (row.prev_hash !== prev) {
      return { ok: false, entries: rows.length, brokenAt: row.id, reason: 'prev_hash does not match the preceding entry' };
    }
    if (digest(prev, row) !== row.hash) {
      return { ok: false, entries: rows.length, brokenAt: row.id, reason: 'entry contents do not match its recorded hash' };
    }
    prev = row.hash;
  }
  return { ok: true, entries: rows.length, head: prev === GENESIS ? null : prev };
}
