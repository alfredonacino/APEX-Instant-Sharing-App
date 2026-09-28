/**
 * Anonymous access to a single file through a public link.
 *
 * This is the only router in the app reachable without a session, so it is
 * deliberately narrow: two GETs, a rate limit, no listing, no enumeration, and
 * nothing here ever reveals anything about the account that owns the file
 * beyond the display name the owner chose to share.
 */
import { Router } from 'express';
import { audit } from '../lib/audit.js';
import { config } from '../config.js';
import { publicLinkLimiter } from '../middleware/rate-limit.js';
import { getSetting } from '../services/settings.service.js';
import * as filesService from '../services/files.service.js';
import { forbidden, gone, notFound } from '../lib/validate.js';

export const publicRouter = Router();
publicRouter.use(publicLinkLimiter);

/** Tokens are base64url from randomToken(32); reject anything else before touching the database. */
const TOKEN_RE = /^[A-Za-z0-9_-]{20,128}$/;

function readToken(value) {
  // Every malformed token gets the same answer as a well-formed unknown one.
  // Reporting "too short" separately would tell someone probing the endpoint
  // what shape a real token has.
  const token = String(value ?? '');
  if (!TOKEN_RE.test(token)) throw notFound('This link is not valid');
  return token;
}

/** Why a known-but-unusable link failed, in words a recipient can act on. */
const REASONS = {
  link_revoked: 'This link has been turned off by the person who shared it',
  link_expired: 'This link has expired',
  file_expired: 'The file behind this link has expired',
  file_deleted: 'The file behind this link has been deleted',
  download_limit_reached: 'This link has reached its download limit',
};

/**
 * Resolve a token into a usable file, or throw.
 * An unknown token is a flat 404; a token that genuinely existed gets 410 and a
 * reason, which is useful to the recipient and tells a guesser nothing they did
 * not already know by holding the token.
 */
function resolveOrThrow(req, token, stage) {
  if (!getSetting('allowPublicLinks')) {
    audit({
      req, action: 'share.link.download', outcome: 'denied', objectType: 'file',
      details: { reason: 'public_links_disabled', stage, tokenPrefix: token.slice(0, 8) },
    });
    throw forbidden('Public link sharing is switched off on this deployment');
  }

  const result = filesService.resolveLink(token);
  if (!result.ok) {
    audit({
      req, action: 'share.link.download', outcome: 'denied',
      objectType: 'file', objectId: result.row?.public_id ?? null,
      objectLabel: result.row?.original_name ?? null,
      details: { reason: result.reason, stage, tokenPrefix: token.slice(0, 8) },
    });
    if (result.reason === 'unknown_token') throw notFound('This link is not valid');
    throw gone(REASONS[result.reason] ?? 'This link is no longer available', result.reason);
  }
  return result.row;
}

/** What the landing page needs in order to describe the download. */
publicRouter.get('/:token', (req, res) => {
  const token = readToken(req.params.token);
  const row = resolveOrThrow(req, token, 'metadata');

  res.setHeader('Cache-Control', 'private, no-store');
  res.json({
    appName: config.appName,
    file: {
      name: row.original_name,
      description: row.description,
      mimeType: row.mime_type,
      size: row.size_bytes,
      sha256: row.sha256,
      createdAt: row.created_at ?? null,
    },
    sharedBy: row.owner_name,
    expiresAt: row.link_expires_at,
    downloadsRemaining:
      row.max_downloads === null ? null : Math.max(row.max_downloads - row.link_download_count, 0),
  });
});

publicRouter.get('/:token/download', (req, res, next) => {
  const token = readToken(req.params.token);
  const row = resolveOrThrow(req, token, 'download');

  const abs = filesService.absoluteBlobPath(row.stored_name);
  filesService.countLinkDownload(row.link_id, row.id);

  audit({
    req, action: 'share.link.download', outcome: 'success', objectType: 'file',
    objectId: row.public_id, objectLabel: row.original_name, targetUserId: row.owner_id,
    details: {
      via: 'public_link',
      size: row.size_bytes,
      sha256: row.sha256,
      owner: row.owner_email,
      // The token itself is the capability, so only a prefix goes in the log.
      tokenPrefix: token.slice(0, 8),
      anonymous: true,
    },
  });

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'private, no-store');
  // An attachment, never inline: a shared upload must not be rendered as a
  // document inside this origin.
  res.download(abs, row.original_name, (error) => {
    if (!error) return;
    if (error.code === 'ENOENT') {
      console.error('[public] blob missing on disk', row.stored_name);
      if (!res.headersSent) return next(notFound('The stored copy of this file is missing'));
    }
    if (!res.headersSent) return next(error);
    res.destroy();
  });
});
