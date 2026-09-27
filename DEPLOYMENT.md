# Deployment standard

Every app generated in this workspace deploys the same way: **rsync to the app
server, run under pm2, watch enabled, restored on reboot.**

| | |
|---|---|
| Server | `$DEPLOY_HOST` (any Linux host you can reach over SSH) |
| User / base directory | `$DEPLOY_USER` / `$DEPLOY_BASE` |
| App directory | `$DEPLOY_BASE/<package.json name>` |
| Process manager | pm2, process name = `<package.json name>` |
| Runtime | pinned Node in `~/.local/node-v<version>`, symlinked `~/.local/node-current` |
| Boot persistence | `pm2 save` + an enabled `pm2-$DEPLOY_USER.service` unit |
| Watch | on, with every runtime-written path excluded |
| TLS | terminated by the app on `3443`; `3210` redirects to it |

## Configure the target first

`deploy.sh` has no server baked into it. Tell it where to deploy once:

```bash
cp .env.deploy.example .env.deploy   # then fill in DEPLOY_HOST and DEPLOY_USER
```

`.env.deploy` is git-ignored, so your server details stay out of the
repository. Key-based SSH to that host must already work without a prompt --
the script connects with `BatchMode=yes`. Any setting can also be given for a
single run: `DEPLOY_HOST=my-server ./deploy.sh`.

## Deploying

```bash
./deploy.sh              # deploy (safe to re-run as often as you like)
./deploy.sh --dry-run    # show what would transfer, change nothing
./deploy.sh --logs       # deploy, then tail the remote logs
```

Overridable per run: `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_BASE`, `APP_NAME`,
`APP_PORT`, `NODE_VERSION`, `GENERATE_SECRETS`, `HEALTH_PATH`.

## What the script does

1. **Preflight** - SSH reachability, pm2 present.
2. **Runtime** - installs the pinned Node under `~/.local` if missing. The
   system Node is 18 and other apps depend on it, so it is never touched;
   this app needs ≥ 22 for the built-in `node:sqlite`.
3. **Sync** - `rsync -az --delete`, excluding `.git`, `node_modules`, `.env`,
   `data/`, `storage/`, `logs/`. Code is replaced, state is preserved.
4. **Dependencies** - `npm ci --omit=dev` using the pinned runtime.
5. **Secrets** - on the *first* deploy only, generates `.env` (mode 600) with
   `APP_KEY` and `SESSION_SECRET`, then appends `deploy/env.production`. Later
   deploys only append settings that are *missing*; nothing already in the file
   is ever changed, so anything tuned on the server survives.
6. **Post-install hook** - `POST_INSTALL_CMD`, here `npm run cert:ensure`,
   which creates a self-signed certificate on the first deploy and leaves an
   existing one (or a real one you installed) alone.
7. **pm2** - `pm2 startOrReload ecosystem.config.cjs --update-env` then
   `pm2 save` so the process list survives a reboot.
8. **Verify** - health check on `https://127.0.0.1:3443/healthz`; prints recent
   logs and exits non-zero if the app did not come up. Certificate validation
   is skipped there on purpose: the check proves the process is listening, and
   a self-signed certificate would fail validation against localhost.

## Why some paths are excluded from watch

`watch: true` restarts the process whenever a file changes. `data/` holds the
SQLite database (which writes WAL files on every request) and `storage/` holds
uploads, so watching them would restart the app on every upload and every
write. `ecosystem.config.cjs` excludes them, plus `logs/`, `node_modules/` and
`.env`. Deploys still restart the app, because `rsync` rewrites the code.

## TLS on this deployment

There is no root on the app server, so there is no nginx and nothing can bind
443. The app terminates TLS itself:

- **https://$DEPLOY_HOST:3443** - the app
- **http://$DEPLOY_HOST:3210** - redirect-only listener, 308 to the HTTPS URL

`deploy.sh` generates a self-signed certificate into `certs/` on the first
deploy, with SANs covering the server's hostname and every one of its IPv4
addresses. Browsers will warn until it is trusted - see the HTTPS section of
the README for the fingerprint check and the import command.

To switch to a certificate from a real CA, put it on the server and add the
paths to `.env` (they are never overwritten by a deploy):

```bash
ssh "$DEPLOY_USER@$DEPLOY_HOST"
cd apex-instant-sharing-app
printf 'SSL_KEY_PATH=/path/privkey.pem\nSSL_CERT_PATH=/path/fullchain.pem\n' >> .env
pm2 restart apex-instant-sharing-app
```

After a renewal, reload without dropping connections:

```bash
pm2 sendSignal SIGHUP apex-instant-sharing-app
```

`certs/` is excluded from the rsync and from pm2's watch list: the certificate
belongs to the server, and watching it would restart the app mid-renewal.

## Never overwritten on the server

- `.env` - holds `APP_KEY`. It encrypts the enrolled TOTP secrets and keys the
  audit hash chain. Replacing it invalidates every authenticator and makes the
  audit chain unverifiable.
- `data/` - the SQLite database (users, files, shares, audit trail).
- `storage/` - the uploaded file bytes.
- `certs/` - the TLS key pair.

Back these three up together; they only make sense as a set.

## First-time server setup

`deploy.sh` expects `pm2` to be on the server already (`npm i -g pm2`). For the
process list to survive a reboot, pm2's systemd unit has to be enabled once per
server -- this is the one step that needs root:

```bash
pm2 startup systemd -u "$USER" --hp "$HOME"   # prints a sudo command to run
pm2 save
```

Until that unit is enabled, `deploy.sh` finishes normally but prints a reminder
at the end of each deploy.

## Rollback

```bash
ssh "$DEPLOY_USER@$DEPLOY_HOST" 'pm2 stop apex-instant-sharing-app'
git checkout <previous-tag> && ./deploy.sh
```

## Reusing this for another app

`deploy.sh` and `ecosystem.config.cjs` are app-agnostic apart from the process
name and port. Copy both, set `APP_PORT`, adjust `GENERATE_SECRETS` for
whatever that app needs, and keep the runtime-written directories in
`ignore_watch` and in the rsync excludes.
