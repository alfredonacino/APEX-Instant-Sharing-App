import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { audit } from '../lib/audit.js';

function make({ windowMs, limit, name, message, keyGenerator }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator,
    handler: (req, res) => {
      audit({ req, action: 'security.rate_limited', outcome: 'denied', details: { limiter: name, path: req.originalUrl } });
      res.status(429).json({ error: message, code: 'rate_limited' });
    },
  });
}

/** Broad protection for the JSON API. */
export const apiLimiter = make({
  name: 'api',
  windowMs: 15 * 60_000,
  limit: 1000,
  message: 'Too many requests - slow down and try again shortly',
});

/** Credential stuffing protection, keyed on the IP and the email being tried. */
export const loginLimiter = make({
  name: 'login',
  windowMs: 15 * 60_000,
  limit: 20,
  message: 'Too many sign-in attempts - wait a few minutes before trying again',
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}|${String(req.body?.email ?? '').toLowerCase()}`,
});

export const registerLimiter = make({
  name: 'register',
  windowMs: 60 * 60_000,
  limit: 10,
  message: 'Too many accounts created from this address - try again later',
});

/** Online brute force of a 6-digit code is the main risk MFA has to resist. */
export const mfaLimiter = make({
  name: 'mfa',
  windowMs: 10 * 60_000,
  limit: 15,
  message: 'Too many verification attempts - wait before trying again',
  keyGenerator: (req) => `${ipKeyGenerator(req.ip)}|${req.session?.userId ?? 'anon'}`,
});

export const uploadLimiter = make({
  name: 'upload',
  windowMs: 60_000,
  limit: 60,
  message: 'Upload rate exceeded - try again in a minute',
});
