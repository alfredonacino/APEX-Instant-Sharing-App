/** Small, dependency-free request validation helpers. */

export class HttpError extends Error {
  constructor(status, message, { code = null, details = null } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.expose = true;
  }
}

export const badRequest = (message, details) => new HttpError(400, message, { code: 'bad_request', details });
export const unauthorized = (message = 'Authentication required') => new HttpError(401, message, { code: 'unauthorized' });
export const forbidden = (message = 'Not permitted') => new HttpError(403, message, { code: 'forbidden' });
export const notFound = (message = 'Not found') => new HttpError(404, message, { code: 'not_found' });
export const conflict = (message) => new HttpError(409, message, { code: 'conflict' });
export const tooMany = (message) => new HttpError(429, message, { code: 'rate_limited' });

export function str(value, field, { min = 1, max = 255, required = true, trim = true } = {}) {
  if (value === undefined || value === null) {
    if (required) throw badRequest(`${field} is required`);
    return '';
  }
  if (typeof value !== 'string') throw badRequest(`${field} must be text`);
  const out = trim ? value.trim() : value;
  if (out.length < min) {
    throw badRequest(required || out.length > 0 ? `${field} must be at least ${min} characters` : `${field} is required`);
  }
  if (out.length > max) throw badRequest(`${field} must be at most ${max} characters`);
  return out;
}

const EMAIL_RE = /^[^\s@]+@[^\s@,]+\.[^\s@,]{2,}$/;

export function email(value) {
  const raw = str(value, 'Email', { max: 254 }).toLowerCase();
  if (!EMAIL_RE.test(raw)) throw badRequest('Enter a valid email address');
  return raw;
}

/**
 * Length is the dominant factor in password strength, so the rule is a long
 * minimum plus a check against the handful of catastrophically common choices.
 */
const WEAK = new Set([
  'password', 'passw0rd', 'password1', 'password123', 'passwordpassword',
  '123456789012', '1234567890123', 'qwertyuiopas', 'letmeinletmein',
  'administrator', 'iloveyouiloveyou', 'welcome12345', 'changeme1234',
]);

export function password(value, { minLength = 12 } = {}) {
  if (typeof value !== 'string') throw badRequest('Password must be text');
  if (value.length < minLength) throw badRequest(`Password must be at least ${minLength} characters`);
  if (value.length > 1024) throw badRequest('Password must be at most 1024 characters');
  const squashed = value.toLowerCase().replace(/\s+/g, '');
  if (WEAK.has(squashed)) throw badRequest('That password is too common - choose something less predictable');
  if (/^(.)\1+$/.test(squashed)) throw badRequest('That password is too predictable');
  return value;
}

export function totpToken(value) {
  const token = String(value ?? '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(token)) throw badRequest('Enter the 6-digit code from your authenticator app');
  return token;
}

export function oneOf(value, allowed, field) {
  if (!allowed.includes(value)) throw badRequest(`${field} must be one of: ${allowed.join(', ')}`);
  return value;
}

export function isoDateOrNull(value, field) {
  if (value === undefined || value === null || value === '') return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw badRequest(`${field} must be a valid date`);
  return date.toISOString();
}

export function idList(value, field, { max = 200 } = {}) {
  if (value === undefined || value === null || value === '') return [];
  const list = Array.isArray(value) ? value : String(value).split(',');
  const cleaned = [...new Set(list.map((v) => String(v).trim()).filter(Boolean))];
  if (cleaned.length > max) throw badRequest(`${field} accepts at most ${max} entries`);
  return cleaned;
}

export function pageParams(query, { defaultLimit = 50, maxLimit = 200 } = {}) {
  const limit = Math.min(Math.max(Number.parseInt(query.limit ?? defaultLimit, 10) || defaultLimit, 1), maxLimit);
  const offset = Math.max(Number.parseInt(query.offset ?? 0, 10) || 0, 0);
  return { limit, offset };
}

/** Strip directory components and control characters from an uploaded filename. */
export function safeFilename(name, fallback = 'file') {
  const base = String(name ?? '')
    .split(/[\\/]/)
    .pop()
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/^\.+/, '')
    .trim();
  return (base || fallback).slice(0, 200);
}
