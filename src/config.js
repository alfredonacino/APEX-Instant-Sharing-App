import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Node >= 20.6 ships .env parsing; missing file is not an error.
try {
  process.loadEnvFile(path.join(ROOT, '.env'));
} catch {
  /* no .env - fall back to real environment variables */
}

const env = process.env;
const isProd = env.NODE_ENV === 'production';

function bool(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function int(value, fallback) {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
}

function resolveDir(value, fallback) {
  const dir = path.resolve(ROOT, value || fallback);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Reads a secret from the environment. In development a generated value is
 * persisted under data/ so restarts do not invalidate sessions or MFA secrets;
 * in production the operator must supply it explicitly.
 */
function secret(name, envValue, bytes, encoding, dataDir) {
  if (envValue) return envValue.trim();
  if (isProd) {
    throw new Error(
      `${name} must be set when NODE_ENV=production. Generate one with:\n` +
        `  node -e "console.log(require('crypto').randomBytes(${bytes}).toString('${encoding}'))"`,
    );
  }
  const file = path.join(dataDir, `.${name.toLowerCase()}`);
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const generated = crypto.randomBytes(bytes).toString(encoding);
  fs.writeFileSync(file, generated, { mode: 0o600 });
  process.emitWarning(`${name} was not set - generated a development value in ${file}`);
  return generated;
}

const dataDir = resolveDir(env.DATA_DIR, './data');
const storageDir = resolveDir(env.STORAGE_DIR, './storage/blobs');

const appKeyHex = secret('APP_KEY', env.APP_KEY, 32, 'hex', dataDir);
if (!/^[0-9a-f]{64}$/i.test(appKeyHex)) {
  throw new Error('APP_KEY must be 64 hexadecimal characters (32 bytes).');
}

export const config = {
  env: env.NODE_ENV || 'development',
  isProd,
  appName: env.APP_NAME || 'APEX Instant Sharing',
  host: env.HOST || '0.0.0.0',
  port: int(env.PORT, 3000),
  trustProxy: int(env.TRUST_PROXY, 0),

  dataDir,
  storageDir,
  dbPath: path.join(dataDir, 'apex.sqlite'),

  appKey: Buffer.from(appKeyHex, 'hex'),
  sessionSecret: secret('SESSION_SECRET', env.SESSION_SECRET, 48, 'base64url', dataDir),

  requireMfa: bool(env.REQUIRE_MFA, true),
  allowSelfRegistration: bool(env.ALLOW_SELF_REGISTRATION, true),
  adminCanDownloadAll: bool(env.ADMIN_CAN_DOWNLOAD_ALL, false),

  maxUploadBytes: int(env.MAX_UPLOAD_MB, 200) * 1024 * 1024,
  maxFilesPerUpload: int(env.MAX_FILES_PER_UPLOAD, 10),

  sessionIdleMs: int(env.SESSION_IDLE_MINUTES, 60) * 60_000,
  sessionAbsoluteMs: int(env.SESSION_ABSOLUTE_HOURS, 12) * 3_600_000,
  cookieSecure: bool(env.COOKIE_SECURE, isProd),

  maxFailedLogins: int(env.MAX_FAILED_LOGINS, 5),
  lockoutMs: int(env.LOCKOUT_MINUTES, 15) * 60_000,

  passwordMinLength: 12,
};
