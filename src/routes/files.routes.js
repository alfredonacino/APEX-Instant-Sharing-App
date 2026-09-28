import path from 'node:path';
import fsp from 'node:fs/promises';
import multer from 'multer';
import { Router } from 'express';
import { config } from '../config.js';
import { db } from '../lib/db.js';
import { audit } from '../lib/audit.js';
import { requireAuth } from '../middleware/auth.js';
import { uploadLimiter } from '../middleware/rate-limit.js';
import * as filesService from '../services/files.service.js';
import * as users from '../services/users.service.js';
import { getSetting } from '../services/settings.service.js';
import { baseUrlFor } from '../lib/urls.js';
import {
  badRequest, conflict, forbidden, notFound, idList, isoDateOrNull, oneOf, pageParams,
  positiveIntOrNull, safeFilename, str,
} from '../lib/validate.js';

export const filesRouter = Router();
filesRouter.use(requireAuth);

// ---------------------------------------------------------------- uploads --

const storage = multer.diskStorage({
  destination(req, file, cb) {
    try {
      const rel = filesService.newStoragePath();
      req._pendingRelDir = path.dirname(rel);
      req._pendingBase = path.basename(rel);
      cb(null, path.join(config.storageDir, path.dirname(rel)));
    } catch (error) {
      cb(error);
    }
  },
  filename(req, file, cb) {
    cb(null, req._pendingBase);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: config.maxUploadBytes, files: config.maxFilesPerUpload, fields: 20, fieldSize: 8192 },
});

const MIME_RE = /^[a-z0-9!#$&^_.+-]{1,80}\/[a-z0-9!#$&^_.+-]{1,120}$/i;
const cleanMime = (value) => (MIME_RE.test(String(value ?? '')) ? String(value) : 'application/octet-stream');

/** Remove blobs written by multer when the request cannot be completed. */
async function discard(files = []) {
  await Promise.all(files.map((f) => fsp.rm(f.path, { force: true }).catch(() => {})));
}

filesRouter.post('/', uploadLimiter, upload.array('files', config.maxFilesPerUpload), async (req, res) => {
  const uploaded = req.files ?? [];
  if (uploaded.length === 0) throw badRequest('Choose at least one file to upload');

  try {
    const visibility = oneOf(req.body?.visibility || 'private', ['private', 'everyone'], 'Visibility');
    const description = str(req.body?.description, 'Description', { required: false, min: 0, max: 500 });
    const expiresAt = isoDateOrNull(req.body?.expiresAt, 'Expiry');
    const message = str(req.body?.message, 'Message', { required: false, min: 0, max: 500 });
    const recipients = idList(req.body?.shareWith, 'Recipients');

    // Resolve recipients before writing anything, so a bad id fails the whole upload.
    const recipientRows = recipients.map((pid) => {
      const row = users.findByPublicId(pid);
      if (!row || row.status !== 'active') throw badRequest(`Unknown recipient: ${pid}`);
      return row;
    });

    const created = [];
    for (const file of uploaded) {
      const rel = path.relative(config.storageDir, file.path);
      const sha256 = await filesService.sha256OfFile(file.path);
      const record = filesService.createFileRecord({
        ownerId: req.currentUser.id,
        originalName: safeFilename(file.originalname),
        storedName: rel,
        mimeType: cleanMime(file.mimetype),
        sizeBytes: file.size,
        sha256,
        description,
        visibility,
        expiresAt,
      });

      audit({
        req, action: 'file.upload', outcome: 'success', objectType: 'file',
        objectId: record.public_id, objectLabel: record.original_name,
        details: { size: record.size_bytes, mimeType: record.mime_type, sha256, visibility, expiresAt },
      });
      if (visibility === 'everyone') {
        audit({
          req, action: 'share.visibility', outcome: 'success', objectType: 'file',
          objectId: record.public_id, objectLabel: record.original_name,
          details: { from: 'private', to: 'everyone', at: 'upload' },
        });
      }

      for (const recipient of recipientRows) {
        filesService.grantShare(record.id, recipient.id, req.currentUser.id, { message, expiresAt });
        audit({
          req, action: 'share.grant', outcome: 'success', objectType: 'file',
          objectId: record.public_id, objectLabel: record.original_name, targetUserId: recipient.id,
          details: { recipient: recipient.email, expiresAt, at: 'upload' },
        });
      }

      created.push(filesService.publicFile(filesService.getForViewer(record.public_id, req.currentUser.id)));
    }

    res.status(201).json({ files: created });
  } catch (error) {
    await discard(uploaded);
    throw error;
  }
});

// ---------------------------------------------------------------- listing --

filesRouter.get('/', (req, res) => {
  const scope = oneOf(req.query.scope || 'all', ['all', 'mine', 'shared', 'everyone', 'admin'], 'Scope');
  if (scope === 'admin' && req.currentUser.role !== 'admin') throw forbidden('Administrator access required');
  const { limit, offset } = pageParams(req.query);
  const q = str(req.query.q, 'Search', { required: false, min: 0, max: 100 });

  const result = filesService.listFiles({
    viewer: req.currentUser,
    scope,
    q,
    limit,
    offset,
    includeDeleted: req.query.includeDeleted === 'true',
  });

  if (scope === 'admin') {
    audit({ req, action: 'file.list', outcome: 'success', details: { scope, q, results: result.files.length } });
  }
  res.json({ ...result, scope, limit, offset });
});

filesRouter.get('/:id', (req, res) => {
  const row = filesService.requireForViewer(req.params.id, req.currentUser.id);
  const access = filesService.decideAccess(row, req.currentUser);
  if (!access.canRead) {
    audit({ req, action: 'file.download', outcome: 'denied', objectType: 'file', objectId: row.public_id, details: { reason: access.reason, stage: 'metadata' } });
    throw notFound('File not found');
  }
  const isManager = row.owner_id === req.currentUser.id || req.currentUser.role === 'admin';
  const live = isManager ? filesService.getLiveLink(row.id) : null;
  res.json({
    file: filesService.publicFile(row),
    access,
    shares: isManager ? filesService.listShares(row.id) : undefined,
    publicLink: live ? filesService.publicLink(live, { baseUrl: baseUrlFor(req) }) : null,
    publicLinksAllowed: isManager ? getSetting('allowPublicLinks') : undefined,
  });
});

// -------------------------------------------------------------- downloads --

filesRouter.get('/:id/download', (req, res, next) => {
  const row = filesService.requireForViewer(req.params.id, req.currentUser.id);
  const access = filesService.decideAccess(row, req.currentUser);

  if (!access.canDownload) {
    audit({
      req, action: 'file.download', outcome: 'denied', objectType: 'file',
      objectId: row.public_id, objectLabel: row.original_name,
      details: { reason: access.reason ?? 'no_grant', owner: row.owner_email },
    });
    throw access.reason === 'admin_download_disabled'
      ? forbidden('Administrators cannot download files they have no grant for on this deployment')
      : notFound('File not found');
  }

  const abs = filesService.absoluteBlobPath(row.stored_name);
  filesService.incrementDownloads(row.id);
  audit({
    req, action: 'file.download', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: row.owner_id,
    details: { via: access.via, size: row.size_bytes, owner: row.owner_email, sha256: row.sha256 },
  });

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'private, no-store');
  // Always an attachment: never render a member's upload inside this origin.
  res.download(abs, row.original_name, (error) => {
    if (!error) return;
    if (error.code === 'ENOENT') {
      console.error('[files] blob missing on disk', row.stored_name);
      if (!res.headersSent) return next(notFound('The stored copy of this file is missing - contact an administrator'));
    }
    if (!res.headersSent) return next(error);
    res.destroy();
  });
});

// ----------------------------------------------------------------- update --

function requireManageable(req) {
  const row = filesService.requireForViewer(req.params.id, req.currentUser.id);
  const isOwner = row.owner_id === req.currentUser.id;
  const isAdmin = req.currentUser.role === 'admin';
  if (!isOwner && !isAdmin) {
    audit({ req, action: 'file.update', outcome: 'denied', objectType: 'file', objectId: row.public_id, details: { reason: 'not_owner' } });
    throw notFound('File not found');
  }
  if (row.deleted_at) throw notFound('File has been deleted');
  return { row, isOwner, adminOverride: !isOwner && isAdmin };
}

filesRouter.patch('/:id', (req, res) => {
  const { row, adminOverride } = requireManageable(req);
  const changes = {};
  if (req.body?.description !== undefined) changes.description = str(req.body.description, 'Description', { required: false, min: 0, max: 500 });
  if (req.body?.visibility !== undefined) changes.visibility = oneOf(req.body.visibility, ['private', 'everyone'], 'Visibility');
  if (req.body?.expiresAt !== undefined) changes.expiresAt = isoDateOrNull(req.body.expiresAt, 'Expiry');
  if (Object.keys(changes).length === 0) throw badRequest('Nothing to update');

  const updated = filesService.updateFile(row.id, changes);

  if (changes.visibility && changes.visibility !== row.visibility) {
    audit({
      req, action: 'share.visibility', outcome: 'success', objectType: 'file',
      objectId: row.public_id, objectLabel: row.original_name,
      details: { from: row.visibility, to: changes.visibility, adminOverride },
    });
  }
  audit({
    req, action: 'file.update', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, details: { ...changes, adminOverride },
  });

  res.json({ file: filesService.publicFile(filesService.getForViewer(updated.public_id, req.currentUser.id)) });
});

filesRouter.delete('/:id', (req, res) => {
  const { row, adminOverride } = requireManageable(req);
  const shareCount = filesService.sharedWithUserIds(row.id).length;
  filesService.softDeleteFile(row.id, req.currentUser.id);
  audit({
    req, action: 'file.delete', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: row.owner_id,
    details: { adminOverride, revokedShares: shareCount, size: row.size_bytes },
  });
  res.json({ ok: true });
});

// ----------------------------------------------------------------- shares --

filesRouter.post('/:id/shares', (req, res) => {
  const { row, adminOverride } = requireManageable(req);
  const recipients = idList(req.body?.userIds ?? req.body?.users, 'Recipients');
  if (recipients.length === 0) throw badRequest('Choose at least one person to share with');
  const message = str(req.body?.message, 'Message', { required: false, min: 0, max: 500 });
  const expiresAt = isoDateOrNull(req.body?.expiresAt, 'Expiry');

  const granted = [];
  for (const pid of recipients) {
    const recipient = users.findByPublicId(pid);
    if (!recipient || recipient.status !== 'active') throw badRequest(`Unknown recipient: ${pid}`);
    if (recipient.id === row.owner_id) continue; // the owner already has access
    filesService.grantShare(row.id, recipient.id, req.currentUser.id, { message, expiresAt });
    audit({
      req, action: 'share.grant', outcome: 'success', objectType: 'file',
      objectId: row.public_id, objectLabel: row.original_name, targetUserId: recipient.id,
      details: { recipient: recipient.email, expiresAt, adminOverride },
    });
    granted.push(recipient.public_id);
  }

  res.json({ granted, shares: filesService.listShares(row.id) });
});

filesRouter.delete('/:id/shares/:userId', (req, res) => {
  const { row, adminOverride } = requireManageable(req);
  const recipient = users.requireByPublicId(req.params.userId);
  const removed = filesService.revokeShare(row.id, recipient.id);
  if (!removed) throw notFound('That person does not have a grant on this file');
  audit({
    req, action: 'share.revoke', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: recipient.id,
    details: { recipient: recipient.email, adminOverride },
  });
  res.json({ ok: true, shares: filesService.listShares(row.id) });
});

// ----------------------------------------------------------- public links --
// A link makes one file reachable without an account, so only the owner (or an
// administrator) may mint one, the administrator can switch the whole feature
// off, and both minting and revoking are audited.

filesRouter.post('/:id/link', (req, res) => {
  if (!getSetting('allowPublicLinks')) {
    const row = filesService.requireForViewer(req.params.id, req.currentUser.id);
    audit({
      req, action: 'share.link.create', outcome: 'denied', objectType: 'file',
      objectId: row.public_id, objectLabel: row.original_name,
      details: { reason: 'public_links_disabled' },
    });
    throw forbidden('Public links are disabled on this deployment');
  }

  const { row, adminOverride } = requireManageable(req);
  const expiresAt = isoDateOrNull(req.body?.expiresAt, 'Link expiry');
  const maxDownloads = positiveIntOrNull(req.body?.maxDownloads, 'Download limit');

  // A link outliving the file it points at would just 404; say so plainly.
  if (row.expires_at && expiresAt && new Date(expiresAt) > new Date(row.expires_at)) {
    throw conflict('The link would outlive the file - the file itself expires ' + row.expires_at);
  }

  const { link, replaced } = filesService.createLink(row.id, req.currentUser.id, { expiresAt, maxDownloads });
  audit({
    req, action: 'share.link.create', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: row.owner_id,
    details: { expiresAt, maxDownloads, rotated: Boolean(replaced), adminOverride },
  });

  res.status(201).json({ publicLink: filesService.publicLink(link, { baseUrl: baseUrlFor(req) }) });
});

filesRouter.patch('/:id/link', (req, res) => {
  const { row, adminOverride } = requireManageable(req);
  const changes = {};
  if (req.body?.expiresAt !== undefined) changes.expiresAt = isoDateOrNull(req.body.expiresAt, 'Link expiry');
  if (req.body?.maxDownloads !== undefined) changes.maxDownloads = positiveIntOrNull(req.body.maxDownloads, 'Download limit');
  if (Object.keys(changes).length === 0) throw badRequest('Nothing to update');

  const updated = filesService.updateLink(row.id, changes);
  if (!updated) throw notFound('This file has no public link');

  audit({
    req, action: 'share.link.create', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: row.owner_id,
    details: { operation: 'update', ...changes, rotated: false, adminOverride },
  });
  res.json({ publicLink: filesService.publicLink(updated, { baseUrl: baseUrlFor(req) }) });
});

filesRouter.delete('/:id/link', (req, res) => {
  const { row, adminOverride } = requireManageable(req);
  const revoked = filesService.revokeLink(row.id, req.currentUser.id);
  if (!revoked) throw notFound('This file has no public link');

  audit({
    req, action: 'share.link.revoke', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: row.owner_id,
    details: { downloads: revoked.download_count, createdAt: revoked.created_at, adminOverride },
  });
  res.json({ ok: true, publicLink: null });
});

/** Who did what with this file - visible to the owner and to administrators. */
filesRouter.get('/:id/activity', (req, res) => {
  const row = filesService.requireForViewer(req.params.id, req.currentUser.id);
  if (row.owner_id !== req.currentUser.id && req.currentUser.role !== 'admin') throw notFound('File not found');
  const { limit, offset } = pageParams(req.query, { defaultLimit: 100 });
  const entries = db
    .prepare(
      `SELECT id, ts, actor_email, action, outcome, details, ip
         FROM audit_log
        WHERE object_type = 'file' AND object_id = ?
        ORDER BY id DESC LIMIT ? OFFSET ?`,
    )
    .all(row.public_id, limit, offset)
    .map((e) => ({ ...e, details: JSON.parse(e.details) }));
  res.json({ entries });
});
