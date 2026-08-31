/**
 * Process entry point: builds the app and binds the port.
 *
 * The factory lives in src/app.js so tests (and anything else that wants an
 * app without a listening socket) can import it directly. This file always
 * listens - no "am I the main module?" check, because process managers such
 * as pm2 launch ESM through a wrapper, which makes process.argv[1] point at
 * the wrapper rather than at this file.
 */
import { createApp } from './src/app.js';
import { config } from './src/config.js';
import { closeDb } from './src/lib/db.js';

const server = createApp().listen(config.port, config.host, () => {
  console.log(`${config.appName} listening on http://${config.host}:${config.port} (${config.env})`);
  console.log(`  storage: ${config.storageDir}`);
  console.log(`  database: ${config.dbPath}`);
  console.log(`  MFA required: ${config.requireMfa} | self-registration: ${config.allowSelfRegistration}`);
  if (!config.cookieSecure) console.log('  note: cookies are not marked Secure - run behind HTTPS in production');
});

const shutdown = (signal) => {
  console.log(`${signal} received, shutting down`);
  server.close(() => {
    closeDb();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (error) => {
  console.error('[fatal] unhandled rejection', error);
});
