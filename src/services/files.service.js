import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { db, nowIso, transaction } from '../lib/db.js';
import { config } from '../config.js';
import { publicId } from '../lib/crypto.js';
import { forbidden, notFound } from '../lib/validate.js';

const FILE_COLUMNS = `
  f.id, f.public_id, f.owner_id, f.original_name, f.stored_name, f.mime_type, f.size_bytes,
  f.sha256, f.description, f.visibility, f.download_count, f.expires_at,
  f.created_at, f.updated_at, f.deleted_at
`;

const ACCESS_CASE = `
  CASE
    WHEN f.owner_id = :viewer THEN 'owner'
    WHEN EXISTS (SELECT 1 FROM file_shares s
                  WHERE s.file_id = f.id AND s.user_id = :viewer
                    AND (s.expires_at IS NULL OR s.expires_at > :now)) THEN 'share'
    WHEN f.visibility = 'everyone' THEN 'everyone'
    ELSE NULL
  END AS access_via
`;

export function publicFile(row) {
  if (!row) return null;
  return {
    id: row.public_id,
    name: row.original_name,
    description: row.description,
    mimeType: row.mime_type,
    size: row.size_bytes,
    sha256: row.sha256,
    visibility: row.visibility,
    downloadCount: row.download_count,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at ?? null,
    accessVia: row.access_via ?? null,
    shareCount: row.share_count ?? 0,
    owner: row.owner_public_id
      ? { id: row.owner_public_id, displayName: row.owner_name, email: row.owner_email }
      : null,
  };
}

// --------------------------------------------------------------- storage ---

/** Blob layout: <STORAGE_DIR>/YYYY/MM/<random>.bin - opaque names, no user input. */
export function newStoragePath() {
  const now = new Date();
  const rel = path.join(
    String(now.getUTCFullYear()),
    String(now.getUTCMonth() + 1).padStart(2, '0'),
    `${crypto.randomBytes(20).toString('hex')}.bin`,
  );
  fs.mkdirSync(path.dirname(path.join(config.storageDir, rel)), { recursive: true });
  return rel;
}

/** Resolve a stored blob, refusing anything that escapes the storage root. */
export function absoluteBlobPath(storedName) {
  const abs = path.resolve(config.storageDir, storedName);
  const root = path.resolve(config.storageDir);
  if (abs !== root && !abs.startsWith(root + path.sep)) throw forbidden('Invalid storage path');
  return abs;
}

export async function sha256OfFile(absPath) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(absPath)) hash.update(chunk);
  return hash.digest('hex');
}

// ----------------------------------------------------------------- CRUD ----

export function createFileRecord({ ownerId, originalName, storedName, mimeType, sizeBytes, sha256, description = '', visibility = 'private', expiresAt = null }) {
  const ts = nowIso();
  const pid = publicId('fil');
  db.prepare(
    `INSERT INTO files (public_id, owner_id, original_name, stored_name, mime_type, size_bytes, sha256,
                        description, visibility, expires_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(pid, ownerId, originalName, storedName, mimeType, sizeBytes, sha256, description, visibility, expiresAt, ts, ts);
  return getRawByPublicId(pid);
}

export function getRawByPublicId(pid) {
  return db.prepare('SELECT * FROM files WHERE public_id = ?').get(String(pid)) ?? null;
}

/** File plus the viewer's access level, or null when the file does not exist. */
export function getForViewer(pid, viewerId) {
  return (
    db
      .prepare(
        `SELECT ${FILE_COLUMNS},
                u.public_id AS owner_public_id, u.display_name AS owner_name, u.email AS owner_email,
                ${ACCESS_CASE},
                (SELECT COUNT(*) FROM file_shares s WHERE s.file_id = f.id) AS share_count
           FROM files f JOIN users u ON u.id = f.owner_id
          WHERE f.public_id = :pid`,
      )
      .get({ pid: String(pid), viewer: viewerId, now: nowIso() }) ?? null
  );
}

export function requireForViewer(pid, viewerId) {
  const row = getForViewer(pid, viewerId);
  if (!row) throw notFound('File not found');
  return row;
}

/**
 * Central authorisation decision for a file.
 * `admin_override` is deliberately distinct so the audit trail shows when an
 * administrator reached past the sharing rules.
 */
export function decideAccess(row, viewer) {
  const expired = row.expires_at && new Date(row.expires_at).getTime() <= Date.now();
  const isOwner = row.owner_id === viewer.id;
  const isAdmin = viewer.role === 'admin';

  if (row.deleted_at) {
    return { canRead: isAdmin || isOwner, canDownload: false, via: isAdmin ? 'admin_override' : 'owner', reason: 'deleted' };
  }
  if (isOwner) return { canRead: true, canDownload: true, via: 'owner', reason: null };
  if (expired) {
    return { canRead: isAdmin, canDownload: false, via: isAdmin ? 'admin_override' : null, reason: 'expired' };
  }
  if (row.access_via === 'share') return { canRead: true, canDownload: true, via: 'share', reason: null };
  if (row.access_via === 'everyone') return { canRead: true, canDownload: true, via: 'everyone', reason: null };
  if (isAdmin) {
    return {
      canRead: true,
      canDownload: config.adminCanDownloadAll,
      via: 'admin_override',
      reason: config.adminCanDownloadAll ? null : 'admin_download_disabled',
    };
  }
  return { canRead: false, canDownload: false, via: null, reason: 'no_grant' };
}

/**
 * List the files a viewer may see.
 *
 * scope: mine (I own it) | shared (granted to me by name) | everyone
 *        (open to all accounts) | all (any of those) | admin (every file,
 *        administrators only).
 */
const SCOPE_FILTER = {
  mine: "access_via = 'owner'",
  shared: "access_via = 'share'",
  everyone: "visibility = 'everyone'",
};

export function listFiles({ viewer, scope = 'all', q = '', limit = 50, offset = 0, includeDeleted = false }) {
  const adminScope = scope === 'admin' && viewer.role === 'admin';
  const params = {
    viewer: viewer.id,
    now: nowIso(),
    q: String(q),
    like: `%${String(q).replace(/[%_]/g, (m) => `\\${m}`)}%`,
  };

  // An expired file stays visible to its owner (so they can see why it went
  // quiet) but to nobody else.
  let filter = '1=1';
  if (!adminScope) {
    filter = "access_via IS NOT NULL AND (access_via = 'owner' OR expires_at IS NULL OR expires_at > :now)";
    if (SCOPE_FILTER[scope]) filter += ` AND ${SCOPE_FILTER[scope]}`;
  }

  const base = `
    SELECT * FROM (
      SELECT ${FILE_COLUMNS},
             u.public_id AS owner_public_id, u.display_name AS owner_name, u.email AS owner_email,
             ${ACCESS_CASE},
             (SELECT COUNT(*) FROM file_shares s WHERE s.file_id = f.id) AS share_count
        FROM files f JOIN users u ON u.id = f.owner_id
       WHERE ${includeDeleted && adminScope ? '1=1' : 'f.deleted_at IS NULL'}
         AND (:q = '' OR f.original_name LIKE :like ESCAPE '\\' OR f.description LIKE :like ESCAPE '\\'
              OR u.display_name LIKE :like ESCAPE '\\' OR u.email LIKE :like ESCAPE '\\')
    )
    WHERE ${filter}
  `;

  const rows = db.prepare(`${base} ORDER BY created_at DESC LIMIT :limit OFFSET :offset`).all({ ...params, limit, offset });
  const total = db.prepare(`SELECT COUNT(*) AS n FROM (${base})`).get(params).n;
  return { files: rows.map(publicFile), total };
}

export function updateFile(fileId, { description, visibility, expiresAt }) {
  const current = db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);
  if (!current) throw notFound('File not found');
  db.prepare('UPDATE files SET description = ?, visibility = ?, expires_at = ?, updated_at = ? WHERE id = ?').run(
    description ?? current.description,
    visibility ?? current.visibility,
    expiresAt === undefined ? current.expires_at : expiresAt,
    nowIso(),
    fileId,
  );
  return db.prepare('SELECT * FROM files WHERE id = ?').get(fileId);
}

export const softDeleteFile = transaction((fileId, actorId) => {
  db.prepare('UPDATE files SET deleted_at = ?, deleted_by = ?, visibility = ?, updated_at = ? WHERE id = ?').run(
    nowIso(), actorId, 'private', nowIso(), fileId,
  );
  db.prepare('DELETE FROM file_shares WHERE file_id = ?').run(fileId);
});

export function incrementDownloads(fileId) {
  db.prepare('UPDATE files SET download_count = download_count + 1 WHERE id = ?').run(fileId);
}

/** Remove the blob from disk. Used by the purge script, never by the API. */
export async function purgeBlob(storedName) {
  await fsp.rm(absoluteBlobPath(storedName), { force: true });
}

// --------------------------------------------------------------- sharing ---

export function listShares(fileId) {
  return db
    .prepare(
      `SELECT s.id, s.message, s.expires_at, s.created_at,
              u.public_id AS user_public_id, u.display_name, u.email,
              g.public_id AS granted_by_public_id, g.display_name AS granted_by_name
         FROM file_shares s
         JOIN users u ON u.id = s.user_id
         JOIN users g ON g.id = s.granted_by
        WHERE s.file_id = ?
        ORDER BY u.display_name COLLATE NOCASE`,
    )
    .all(fileId)
    .map((r) => ({
      user: { id: r.user_public_id, displayName: r.display_name, email: r.email },
      grantedBy: { id: r.granted_by_public_id, displayName: r.granted_by_name },
      message: r.message,
      expiresAt: r.expires_at,
      createdAt: r.created_at,
    }));
}

export const grantShare = transaction((fileId, userId, grantedBy, { message = '', expiresAt = null } = {}) => {
  db.prepare(
    `INSERT INTO file_shares (file_id, user_id, granted_by, message, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(file_id, user_id) DO UPDATE SET
       granted_by = excluded.granted_by, message = excluded.message, expires_at = excluded.expires_at`,
  ).run(fileId, userId, grantedBy, message, expiresAt, nowIso());
});

export function revokeShare(fileId, userId) {
  return db.prepare('DELETE FROM file_shares WHERE file_id = ? AND user_id = ?').run(fileId, userId).changes > 0;
}

export function sharedWithUserIds(fileId) {
  return db.prepare('SELECT user_id FROM file_shares WHERE file_id = ?').all(fileId).map((r) => r.user_id);
}

// ----------------------------------------------------------------- stats ---

export function storageStats() {
  const files = db
    .prepare(
      `SELECT COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS bytes,
              COALESCE(SUM(download_count), 0) AS downloads
         FROM files WHERE deleted_at IS NULL`,
    )
    .get();
  const deleted = db.prepare('SELECT COUNT(*) AS count FROM files WHERE deleted_at IS NOT NULL').get().count;
  const shares = db.prepare('SELECT COUNT(*) AS count FROM file_shares').get().count;
  const everyone = db.prepare(`SELECT COUNT(*) AS count FROM files WHERE visibility = 'everyone' AND deleted_at IS NULL`).get().count;
  const users = db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
                                   SUM(mfa_enabled) AS withMfa FROM users`).get();
  return {
    files: files.count,
    bytes: files.bytes,
    downloads: files.downloads,
    deletedFiles: deleted,
    shares,
    sharedWithEveryone: everyone,
    users: { total: users.total, active: users.active ?? 0, withMfa: users.withMfa ?? 0 },
  };
}
