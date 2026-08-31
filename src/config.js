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

// ------------------------------------------------------------------ TLS ---
// Certificates live outside data/ and storage/ so backups of app state and of
// TLS material stay separate concerns.
const certDir = resolveDir(env.CERT_DIR, './certs');
const sslKeyPath = path.resolve(ROOT, env.SSL_KEY_PATH || path.join(certDir, 'server.key'));
const sslCertPath = path.resolve(ROOT, env.SSL_CERT_PATH || path.join(certDir, 'server.crt'));
const sslCaPath = env.SSL_CA_PATH ? path.resolve(ROOT, env.SSL_CA_PATH) : null;

// Unset SSL_ENABLED means "on if a key pair is sitting there", so dropping in
// a certificate is all it takes; set it explicitly to force either way.
const sslMaterialPresent = fs.existsSync(sslKeyPath) && fs.existsSync(sslCertPath);
const sslEnabled = bool(env.SSL_ENABLED, sslMaterialPresent);

// Deliberately not thrown here: `npm run cert:generate` has to be able to load
// this module in order to learn where the certificate belongs. Starting the
// server without the material is what fails, in src/runtime.js.
export const sslMaterialMissing =
  sslEnabled && !sslMaterialPresent
    ? `SSL is enabled but the certificate is missing.\n` +
      `  expected key : ${sslKeyPath}\n` +
      `  expected cert: ${sslCertPath}\n` +
      `Generate a self-signed pair with:  npm run cert:generate\n` +
      `or point SSL_KEY_PATH / SSL_CERT_PATH at your own certificate.`
    : null;

export const config = {
  env: env.NODE_ENV || 'development',
  isProd,
  appName: env.APP_NAME || 'APEX Instant Sharing',
  host: env.HOST || '0.0.0.0',
  // Hostname used when the app has to build an absolute URL for itself and the
  // request's Host header cannot be trusted (the HTTP -> HTTPS redirect).
  publicHost: env.PUBLIC_HOST || null,
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
  // Secure cookies are only sent over HTTPS, so they follow TLS by default:
  // forcing them on for a plain-HTTP deployment silently breaks sign-in.
  cookieSecure: bool(env.COOKIE_SECURE, isProd || sslEnabled),

  ssl: {
    enabled: sslEnabled,
    keyPath: sslKeyPath,
    certPath: sslCertPath,
    caPath: sslCaPath,
    certDir,
    passphrase: env.SSL_PASSPHRASE || undefined,
    port: int(env.HTTPS_PORT, 3443),
    // A plain-HTTP listener on `port` that sends every request to HTTPS.
    redirectHttp: bool(env.HTTP_REDIRECT, true),
    minVersion: env.SSL_MIN_VERSION || 'TLSv1.2',
  },

  maxFailedLogins: int(env.MAX_FAILED_LOGINS, 5),
  lockoutMs: int(env.LOCKOUT_MINUTES, 15) * 60_000,

  passwordMinLength: 12,
};
