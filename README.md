# APEX Instant Sharing

A shared drop folder for a team: registered members upload files and hand them
to **one named colleague, several, or everyone with an account**. Every account
is protected by a second factor, and everything that happens to a file is
written to an append-only audit trail.

```
Node 24 · Express 5 · SQLite (node:sqlite) · vanilla-JS front end · no build step
```

## What it does

**Accounts**
- Email + password registration; the first account created becomes the administrator.
- TOTP two-factor authentication (Google Authenticator, 1Password, Aegis, ...),
  mandatory by default - an account cannot reach any file until it has enrolled.
- Ten single-use backup codes issued at enrolment, regenerable from Account.
- Lockout after repeated failures, administrator unlock, forced re-enrolment
  when someone loses their phone.

**Sharing**
- Drag-and-drop upload of up to 10 files at a time (200 MB each by default).
- Share with named people, or flip a file to *everyone with an account*.
- Optional expiry on a file or on an individual grant; revoke at any time.
- Four views: everything I can see / my files / shared with me / shared with
  everyone, plus an admin view of every file in the system.

**Audit**
- Every sign-in, enrolment, upload, download, share, revoke, deletion and
  administrator action is recorded with actor, IP, user agent and details.
- The log is append-only (SQLite triggers refuse `UPDATE` and `DELETE`) and
  hash-chained with an HMAC keyed by `APP_KEY`, so an edit made directly
  against the database file is detectable. "Verify integrity" in the admin
  panel walks the whole chain.
- Members see their own trail; administrators can filter and export CSV.

## Running it locally

```bash
npm install
npm start            # http://localhost:3000
```

`data/` (SQLite database) and `storage/blobs/` (uploaded bytes) are created on
first run, along with development values for `APP_KEY` and `SESSION_SECRET`.
Register in the browser - the first account gets administrator rights.

```bash
npm test             # 25 end-to-end tests against a live server instance
npm run dev          # restart on change
```

`npm test` takes ~30 s: one test deliberately waits for a fresh TOTP window to
prove a code cannot be replayed.

## Configuration

Copy `.env.example` to `.env`. `APP_KEY` and `SESSION_SECRET` are **required**
in production; everything else has a working default.

| Setting | Default | Notes |
|---|---|---|
| `REQUIRE_MFA` | `true` | every account must enrol before it can use the app |
| `ALLOW_SELF_REGISTRATION` | `true` | `false` = administrators create accounts |
| `ADMIN_CAN_DOWNLOAD_ALL` | `false` | admins always see metadata; `true` also lets them download anything (audited as `admin_override`) |
| `MAX_UPLOAD_MB` | `200` | per file |
| `SESSION_IDLE_MINUTES` / `SESSION_ABSOLUTE_HOURS` | `60` / `12` | idle and hard session limits |
| `MAX_FAILED_LOGINS` / `LOCKOUT_MINUTES` | `5` / `15` | lockout policy |
| `COOKIE_SECURE` | follows TLS | Secure cookies are only sent over HTTPS, so this tracks `SSL_ENABLED` |
| `SSL_ENABLED` | on if a key pair is present | see [HTTPS](#https) |
| `HTTPS_PORT` / `HTTP_REDIRECT` | `3443` / `true` | HTTPS port, and whether `PORT` redirects to it |

`APP_KEY` encrypts stored TOTP secrets **and** keys the audit chain. Rotating
it invalidates every enrolled authenticator and makes existing audit entries
unverifiable.

## HTTPS

The app terminates TLS itself, so it needs no reverse proxy and no root.

```bash
npm run cert:generate     # self-signed, valid 825 days
npm start                 # a present key pair turns TLS on by itself
```

```
listening on https://0.0.0.0:3443
listening on http://0.0.0.0:3000 (redirects to HTTPS)
TLS: CN=files.example.lan | self-signed
     expires Dec  3 12:18:42 2028 (825 days) | SHA-256 44:F9:16:...
```

With TLS on, the plain-HTTP port becomes a redirect-only listener (308, so a
POST stays a POST), session and CSRF cookies are marked `Secure`, HSTS is sent,
and the CSP gains `upgrade-insecure-requests`. The redirect refuses to build a
URL from a Host header it cannot parse, so it can never become an open
redirect.

**Certificates.** `npm run cert:generate` puts every name the machine answers
to into `subjectAltName` - hostname, `localhost`, and each non-internal IPv4
address - because browsers ignore the legacy CN and reject a certificate with
no matching SAN, including for a bare IP. For a certificate that is trusted
without a warning, point the config at a real one:

```bash
SSL_KEY_PATH=/etc/letsencrypt/live/example.com/privkey.pem
SSL_CERT_PATH=/etc/letsencrypt/live/example.com/fullchain.pem
SSL_CA_PATH=                     # only if your CA ships a separate chain
```

**Renewal without downtime.** Send `SIGHUP` and the new certificate is loaded
into the running process; existing connections are untouched.

```bash
kill -HUP $(pgrep -f 'node server.js')     # or: pm2 sendSignal SIGHUP <app>
```

**Trusting a self-signed certificate.** Browsers warn until you tell them not
to. Compare the SHA-256 printed at startup, then either accept the warning
once, or import it - for Chrome on Linux:

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "apex-instant-sharing" -i certs/server.crt
```

A self-signed certificate encrypts the traffic but proves nothing about who is
on the other end. On a network where that matters, use a real CA.

## Administration

```bash
node scripts/create-admin.js --email a@b.com --name "Ada" --password "..."
node scripts/create-admin.js --email a@b.com --promote
node scripts/purge-deleted.js --days 30 [--dry-run]   # drop bytes of long-deleted files
```

`purge-deleted.js` removes only the stored blob; the database row and the audit
history stay.

## Deployment

`./deploy.sh` - rsync to the app server, pm2 with watch, restored on reboot.
See [DEPLOYMENT.md](DEPLOYMENT.md).

## How it is put together

```
server.js                 express app assembly, helmet CSP, graceful shutdown
src/config.js             environment, key generation, policy
src/lib/db.js             schema, migrations, audit triggers
src/lib/audit.js          hash-chained audit writer + chain verifier
src/lib/crypto.js         scrypt passwords, AES-GCM secrets, backup codes
src/lib/totp.js           TOTP enrolment and verification
src/lib/session-store.js  SQLite-backed express-session store
src/middleware/           auth stages, CSRF, rate limits, error mapping
src/services/             users and files data access + authorisation
src/routes/               auth, files, users, admin endpoints
public/                   single-page front end (no framework, no build)
tests/app.test.js         end-to-end HTTP tests
```

### Security notes

- Passwords: scrypt (N=32768, r=8) with a per-user salt.
- TOTP secrets: AES-256-GCM encrypted at rest; backup codes stored as keyed
  digests, burned on use.
- Sign-in is a two-stage session: a password alone leaves the session at
  `mfa_required` (or `mfa_setup`) and reaches no file endpoint.
- A used TOTP step is recorded so the same code cannot be replayed.
- CSRF: double-submit token plus `SameSite=Lax` cookies.
- Uploads are stored under opaque random names outside the web root and always
  served as `Content-Disposition: attachment` with `nosniff`, so an uploaded
  HTML file can never execute in the app's origin.
- Files are addressed by unguessable public ids; a member with no grant gets
  `404`, not `403`, so the existence of a file is not disclosed.
- Strict CSP, no inline scripts, no third-party origins.
