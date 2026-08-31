# Deployment standard

Every app generated in this workspace deploys the same way: **rsync to the app
server, run under pm2, watch enabled, restored on reboot.**

| | |
|---|---|
| Server | `app-server.example.internal` (Ubuntu 24.04, `app-server`) |
| User / base directory | `deploy` / `/home/deploy` |
| App directory | `/home/deploy/<package.json name>` |
| Process manager | pm2, process name = `<package.json name>` |
| Runtime | pinned Node in `~/.local/node-v<version>`, symlinked `~/.local/node-current` |
| Boot persistence | `pm2 save` + the enabled `pm2-deploy.service` unit |
| Watch | on, with every runtime-written path excluded |

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
   `APP_KEY` and `SESSION_SECRET`, then appends `deploy/env.production`.
   Later deploys leave it alone.
6. **pm2** - `pm2 startOrReload ecosystem.config.cjs --update-env` then
   `pm2 save` so the process list survives a reboot.
7. **Verify** - health check on `/healthz`; prints recent logs and exits
   non-zero if the app did not come up.

## Why some paths are excluded from watch

`watch: true` restarts the process whenever a file changes. `data/` holds the
SQLite database (which writes WAL files on every request) and `storage/` holds
uploads, so watching them would restart the app on every upload and every
write. `ecosystem.config.cjs` excludes them, plus `logs/`, `node_modules/` and
`.env`. Deploys still restart the app, because `rsync` rewrites the code.

## Never overwritten on the server

- `.env` - holds `APP_KEY`. It encrypts the enrolled TOTP secrets and keys the
  audit hash chain. Replacing it invalidates every authenticator and makes the
  audit chain unverifiable.
- `data/` - the SQLite database (users, files, shares, audit trail).
- `storage/` - the uploaded file bytes.

Back these three up together; they only make sense as a set.

## First-time server setup (already done here)

`pm2-deploy.service` is enabled, so `pm2 save` is enough. On a fresh
server, run once:

```bash
pm2 startup systemd -u deploy --hp /home/deploy   # prints a sudo command
pm2 save
```

## Rollback

```bash
ssh deploy@app-server.example.internal 'pm2 stop apex-instant-sharing-app'
git checkout <previous-tag> && ./deploy.sh
```

## Reusing this for another app

`deploy.sh` and `ecosystem.config.cjs` are app-agnostic apart from the process
name and port. Copy both, set `APP_PORT`, adjust `GENERATE_SECRETS` for
whatever that app needs, and keep the runtime-written directories in
`ignore_watch` and in the rsync excludes. Master copies live in
`~/.claude/deploy/`.
