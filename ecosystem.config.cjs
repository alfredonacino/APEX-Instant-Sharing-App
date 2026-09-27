/**
 * pm2 process definition - part of the standard deployment
 * (see DEPLOYMENT.md). Used by ./deploy.sh on the app server and usable
 * locally with `pm2 start ecosystem.config.cjs`.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// The app needs Node >= 22 for node:sqlite. The server's system Node may be
// older, so deploy.sh installs a pinned runtime and points pm2 at it.
const PINNED_NODE =
  process.env.PM2_NODE_INTERPRETER || path.join(os.homedir(), '.local', 'node-current', 'bin', 'node');
const interpreter = fs.existsSync(PINNED_NODE) ? PINNED_NODE : 'node';

module.exports = {
  apps: [
    {
      name: 'apex-instant-sharing-app',
      script: 'server.js',
      cwd: __dirname,
      interpreter,
      instances: 1,
      exec_mode: 'fork',

      // Restart on code changes, as requested. Everything the running app
      // writes to is excluded - watching data/ or storage/ would restart the
      // process on every upload and on every SQLite WAL write.
      watch: true,
      ignore_watch: [
        'node_modules', '.git', 'data', 'storage', 'logs', 'tests', 'certs',
        '\\.env$', '\\.sqlite', '\\.sqlite-wal', '\\.sqlite-shm', '\\.log$',
      ],
      watch_delay: 2000,
      watch_options: { followSymlinks: false, usePolling: false },

      autorestart: true,
      restart_delay: 2000,
      max_restarts: 15,
      min_uptime: '20s',
      max_memory_restart: '512M',
      kill_timeout: 8000,

      env: { NODE_ENV: 'production' },

      error_file: path.join(__dirname, 'logs/error.log'),
      out_file: path.join(__dirname, 'logs/out.log'),
      merge_logs: true,
      time: true,
    },
  ],
};
