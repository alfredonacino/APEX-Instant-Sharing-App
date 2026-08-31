import http from 'node:http';
import https from 'node:https';
import { createApp } from './app.js';
import { config as defaultConfig, sslMaterialMissing } from './config.js';
import { closeDb } from './lib/db.js';
import { describeCertificate, httpsRedirectHandler, tlsOptions } from './lib/tls.js';

const listen = (server, port, host) =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });

/**
 * Bring the app up.
 *
 * With TLS on: an HTTPS listener plus (unless disabled) a plain-HTTP listener
 * that redirects to it. With TLS off: one HTTP listener. Tests pass port 0 to
 * get ephemeral ports.
 */
export async function start({ config = defaultConfig, app = createApp(), port, httpsPort } = {}) {
  const servers = [];
  const urls = [];
  let httpsServer = null;
  let httpServer = null;

  if (config.ssl.enabled) {
    if (sslMaterialMissing) throw new Error(sslMaterialMissing);
    httpsServer = https.createServer(tlsOptions(config.ssl), app);
    const boundHttpsPort = await listen(httpsServer, httpsPort ?? config.ssl.port, config.host);
    servers.push(httpsServer);
    urls.push(`https://${config.host}:${boundHttpsPort}`);

    if (config.ssl.redirectHttp) {
      httpServer = http.createServer(
        httpsRedirectHandler(() => boundHttpsPort, { publicHost: config.publicHost }),
      );
      const boundHttpPort = await listen(httpServer, port ?? config.port, config.host);
      servers.push(httpServer);
      urls.push(`http://${config.host}:${boundHttpPort} (redirects to HTTPS)`);
    }
  } else {
    httpServer = http.createServer(app);
    const boundPort = await listen(httpServer, port ?? config.port, config.host);
    servers.push(httpServer);
    urls.push(`http://${config.host}:${boundPort}`);
  }

  /**
   * Swap in a renewed certificate without dropping connections.
   * Existing TLS sessions keep the old context; new handshakes get the new one.
   */
  const reloadCertificate = () => {
    if (!httpsServer) return false;
    httpsServer.setSecureContext(tlsOptions(config.ssl));
    return true;
  };

  const close = () =>
    Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));

  return {
    app,
    httpsServer,
    httpServer,
    servers,
    urls,
    httpsPort: httpsServer?.address()?.port ?? null,
    httpPort: httpServer?.address()?.port ?? null,
    reloadCertificate,
    close,
  };
}

/** Startup banner + signal handling for the real process. */
export function attachProcessHandlers(runtime, { config = defaultConfig } = {}) {
  console.log(`${config.appName} (${config.env})`);
  for (const url of runtime.urls) console.log(`  listening on ${url}`);
  console.log(`  storage: ${config.storageDir}`);
  console.log(`  database: ${config.dbPath}`);
  console.log(`  MFA required: ${config.requireMfa} | self-registration: ${config.allowSelfRegistration}`);

  if (config.ssl.enabled) {
    const cert = describeCertificate(config.ssl);
    if (cert.error) {
      console.log(`  TLS: certificate could not be inspected (${cert.error})`);
    } else {
      console.log(`  TLS: ${cert.subject} | ${cert.selfSigned ? 'self-signed' : `issued by ${cert.issuer}`}`);
      console.log(`       expires ${cert.validTo} (${cert.expiresInDays} days) | SHA-256 ${cert.fingerprint}`);
      if (cert.expiresInDays < 30) console.log('       !! certificate expires soon - renew it');
      if (cert.selfSigned) console.log('       browsers will warn until this certificate is trusted (see README)');
    }
    console.log('  send SIGHUP after renewing to load a new certificate without a restart');
  } else {
    console.log('  TLS: disabled - traffic is plain HTTP');
    if (config.cookieSecure) {
      console.log('       !! COOKIE_SECURE is on without TLS: sign-in cookies will never be sent');
    }
  }

  process.on('SIGHUP', () => {
    try {
      console.log(runtime.reloadCertificate() ? 'SIGHUP: certificate reloaded' : 'SIGHUP: TLS is not enabled');
    } catch (error) {
      console.error('SIGHUP: certificate reload failed, keeping the current one', error);
    }
  });

  const shutdown = async (signal) => {
    console.log(`${signal} received, shutting down`);
    const forced = setTimeout(() => process.exit(1), 10_000);
    forced.unref();
    await runtime.close();
    closeDb();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', (error) => console.error('[fatal] unhandled rejection', error));
}
