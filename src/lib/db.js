import { DatabaseSync } from 'node:sqlite';
import { config } from '../config.js';

export const db = new DatabaseSync(config.dbPath);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;
  PRAGMA synchronous = NORMAL;
`);

const SCHEMA = `
-- ---------------------------------------------------------------- accounts --
CREATE TABLE IF NOT EXISTS users (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id          TEXT    NOT NULL UNIQUE,
  email              TEXT    NOT NULL UNIQUE,
  display_name       TEXT    NOT NULL,
  password_hash      TEXT    NOT NULL,
  role               TEXT    NOT NULL DEFAULT 'user'   CHECK (role IN ('user','admin')),
  status             TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  mfa_enabled        INTEGER NOT NULL DEFAULT 0        CHECK (mfa_enabled IN (0,1)),
  mfa_secret         TEXT,
  mfa_enrolled_at    TEXT,
  mfa_last_step      INTEGER,
  failed_login_count INTEGER NOT NULL DEFAULT 0,
  locked_until       TEXT,
  last_login_at      TEXT,
  password_changed_at TEXT,
  created_at         TEXT    NOT NULL,
  updated_at         TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT    NOT NULL,
  used_at    TEXT,
  created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON mfa_backup_codes(user_id, used_at);

-- ------------------------------------------------------------------- files --
CREATE TABLE IF NOT EXISTS files (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id      TEXT    NOT NULL UNIQUE,
  owner_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name  TEXT    NOT NULL,
  stored_name    TEXT    NOT NULL,
  mime_type      TEXT    NOT NULL DEFAULT 'application/octet-stream',
  size_bytes     INTEGER NOT NULL,
  sha256         TEXT    NOT NULL,
  description    TEXT    NOT NULL DEFAULT '',
  visibility     TEXT    NOT NULL DEFAULT 'private' CHECK (visibility IN ('private','everyone')),
  download_count INTEGER NOT NULL DEFAULT 0,
  expires_at     TEXT,
  created_at     TEXT    NOT NULL,
  updated_at     TEXT    NOT NULL,
  deleted_at     TEXT,
  deleted_by     INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_files_owner      ON files(owner_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_files_visibility ON files(visibility, deleted_at);
CREATE INDEX IF NOT EXISTS idx_files_created    ON files(created_at DESC);

-- Explicit person-to-person grants. Revoking removes the row; the audit log
-- keeps the history, so nothing is lost.
CREATE TABLE IF NOT EXISTS file_shares (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_by INTEGER NOT NULL REFERENCES users(id),
  message    TEXT    NOT NULL DEFAULT '',
  expires_at TEXT,
  created_at TEXT    NOT NULL,
  UNIQUE (file_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_shares_user ON file_shares(user_id);

-- ---------------------------------------------------------------- sessions --
CREATE TABLE IF NOT EXISTS sessions (
  sid        TEXT    PRIMARY KEY,
  user_id    INTEGER,
  data       TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- --------------------------------------------------------------- audit log --
-- Append-only and hash-chained: every row commits to its predecessor, so any
-- edit or deletion made directly against the database becomes detectable.
CREATE TABLE IF NOT EXISTS audit_log (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             TEXT    NOT NULL,
  actor_id       INTEGER,
  actor_email    TEXT,
  actor_role     TEXT,
  action         TEXT    NOT NULL,
  outcome        TEXT    NOT NULL CHECK (outcome IN ('success','failure','denied')),
  object_type    TEXT,
  object_id      TEXT,
  object_label   TEXT,
  target_user_id INTEGER,
  ip             TEXT,
  user_agent     TEXT,
  details        TEXT    NOT NULL DEFAULT '{}',
  prev_hash      TEXT    NOT NULL,
  hash           TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_object ON audit_log(object_type, object_id, id DESC);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
`;

db.exec(SCHEMA);

/**
 * Additive migrations for databases created by an earlier version.
 * SQLite has no "ADD COLUMN IF NOT EXISTS", so the column list is checked first.
 */
function ensureColumn(table, column, definition) {
  const exists = db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
  if (!exists) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

ensureColumn('users', 'mfa_last_step', 'INTEGER');

/** Wrap a function in a transaction (node:sqlite has no helper of its own). */
export function transaction(fn) {
  return (...args) => {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn(...args);
      db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* rollback of an already-aborted transaction is not interesting */
      }
      throw error;
    }
  };
}

export function nowIso() {
  return new Date().toISOString();
}

/** SQLite has no boolean type; normalise for binding and for JSON output. */
export const toInt = (value) => (value ? 1 : 0);
export const toBool = (value) => value === 1 || value === true;

export function closeDb() {
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } catch {
    /* ignore */
  }
  db.close();
}
