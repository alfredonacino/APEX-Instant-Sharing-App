import { config } from '../config.js';
import { randomToken, timingSafeEquals } from '../lib/crypto.js';
import { audit } from '../lib/audit.js';

const COOKIE = 'apex.csrf';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function parseCookies(header = '') {
  const jar = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    jar[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return jar;
}

/**
 * Double-submit CSRF protection: a non-HttpOnly cookie the page's JavaScript
 * echoes back in the X-CSRF-Token header. Combined with SameSite=Lax this
 * blocks cross-site form posts and cross-origin fetches.
 */
export function csrf(req, res, next) {
  const jar = parseCookies(req.headers.cookie);
  let token = jar[COOKIE];

  if (!token || token.length < 32) {
    token = randomToken(32);
    res.cookie(COOKIE, token, {
      httpOnly: false,
      sameSite: 'lax',
      secure: config.cookieSecure,
      path: '/',
      maxAge: config.sessionAbsoluteMs,
    });
  }
  req.csrfToken = token;

  if (SAFE_METHODS.has(req.method)) return next();

  const provided = req.get('x-csrf-token') || req.body?._csrf;
  if (!provided || !timingSafeEquals(provided, token)) {
    audit({ req, action: 'security.csrf_rejected', outcome: 'denied', details: { path: req.originalUrl, method: req.method } });
    return res.status(403).json({ error: 'Invalid or missing CSRF token - reload the page and try again', code: 'csrf' });
  }
  return next();
}
