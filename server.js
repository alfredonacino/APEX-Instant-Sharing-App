import path from 'node:path';
import { pathToFileURL } from 'node:url';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import { config, ROOT } from './src/config.js';
import { closeDb } from './src/lib/db.js';
import { sessionStore } from './src/lib/session-store.js';
import { csrf } from './src/middleware/csrf.js';
import { loadUser, publicPolicy } from './src/middleware/auth.js';
import { apiLimiter } from './src/middleware/rate-limit.js';
import { errorHandler, notFoundHandler } from './src/middleware/errors.js';
import { authRouter } from './src/routes/auth.routes.js';
import { filesRouter } from './src/routes/files.routes.js';
import { usersRouter } from './src/routes/users.routes.js';
import { adminRouter } from './src/routes/admin.routes.js';

export function createApp() {
  const app = express();

  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'img-src': ["'self'", 'data:'],       // data: carries the enrolment QR code
          'font-src': ["'self'"],
          'connect-src': ["'self'"],
          'form-action': ["'self'"],
          'frame-ancestors': ["'none'"],
          'base-uri': ["'none'"],
          'object-src': ["'none'"],
        },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'same-origin' },
      hsts: config.cookieSecure ? { maxAge: 15552000, includeSubDomains: true } : false,
    }),
  );

  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false, limit: '256kb' }));

  app.use(
    session({
      name: 'apex.sid',
      secret: config.sessionSecret,
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      rolling: true,                 // idle timeout, refreshed on activity
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: config.cookieSecure,
        maxAge: config.sessionIdleMs,
        path: '/',
      },
    }),
  );

  app.use(csrf);
  app.use(loadUser);

  app.get('/healthz', (req, res) => res.json({ ok: true, name: config.appName }));
  app.get('/api/policy', (req, res) => res.json({ policy: publicPolicy(), csrfToken: req.csrfToken }));

  app.use('/api', apiLimiter);
  app.use('/api/auth', authRouter);
  app.use('/api/files', filesRouter);
  app.use('/api/users', usersRouter);
  app.use('/api/admin', adminRouter);

  app.use(express.static(path.join(ROOT, 'public'), { index: 'index.html', maxAge: config.isProd ? '1h' : 0 }));

  app.use('/api', notFoundHandler);
  // Anything else is a browser navigation: hand back the single-page shell.
  app.get(/^(?!\/api\/).*/, (req, res) => res.sendFile(path.join(ROOT, 'public', 'index.html')));

  app.use(errorHandler);
  return app;
}

// Started directly (not imported by a test), so bind the port.
// pathToFileURL matters here: a project path containing spaces would not match
// a hand-built file:// string.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createApp();
  const server = app.listen(config.port, config.host, () => {
    console.log(`${config.appName} listening on http://${config.host}:${config.port} (${config.env})`);
    console.log(`  storage: ${config.storageDir}`);
    console.log(`  database: ${config.dbPath}`);
    console.log(`  MFA required: ${config.requireMfa} | self-registration: ${config.allowSelfRegistration}`);
    if (!config.cookieSecure) console.log('  note: cookies are not marked Secure - run behind HTTPS in production');
  });

  const shutdown = (signal) => {
    console.log(`\n${signal} received, shutting down`);
    server.close(() => {
      closeDb();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}
