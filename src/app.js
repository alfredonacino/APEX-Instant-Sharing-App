import path from 'node:path';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import { config, ROOT } from './config.js';
import { sessionStore } from './lib/session-store.js';
import { csrf } from './middleware/csrf.js';
import { loadUser, publicPolicy } from './middleware/auth.js';
import { apiLimiter } from './middleware/rate-limit.js';
import { errorHandler, notFoundHandler } from './middleware/errors.js';
import { authRouter } from './routes/auth.routes.js';
import { filesRouter } from './routes/files.routes.js';
import { usersRouter } from './routes/users.routes.js';
import { adminRouter } from './routes/admin.routes.js';

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
          // Only meaningful over TLS; tells the browser to fetch any stray
          // http:// subresource over https instead of blocking it.
          ...(config.ssl.enabled ? { 'upgrade-insecure-requests': [] } : {}),
        },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'same-origin' },
      // HSTS is only honoured over HTTPS, and pinning it on a plain-HTTP
      // deployment would be a foot-gun, so it follows TLS.
      hsts: config.ssl.enabled || config.cookieSecure ? { maxAge: 15552000, includeSubDomains: true } : false,
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

  // Assets are not content-hashed, so they must be revalidated rather than
  // cached by time: a client holding an hour-old index.html or app.js after a
  // deploy talks to an API it no longer matches. ETag makes revalidation a
  // cheap 304.
  app.use(
    express.static(path.join(ROOT, 'public'), {
      index: 'index.html',
      etag: true,
      lastModified: true,
      maxAge: 0,
      setHeaders: (res) => res.setHeader('Cache-Control', 'no-cache'),
    }),
  );

  app.use('/api', notFoundHandler);
  // Anything else is a browser navigation: hand back the single-page shell.
  app.get(/^(?!\/api\/).*/, (req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(path.join(ROOT, 'public', 'index.html'));
  });

  app.use(errorHandler);
  return app;
}
