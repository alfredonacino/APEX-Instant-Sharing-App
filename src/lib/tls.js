import fs from 'node:fs';
import crypto from 'node:crypto';
import { config } from '../config.js';

/** Read the key pair (and optional chain) from disk. */
export function readTlsMaterial(ssl = config.ssl) {
  const material = {
    key: fs.readFileSync(ssl.keyPath),
    cert: fs.readFileSync(ssl.certPath),
  };
  if (ssl.caPath) material.ca = fs.readFileSync(ssl.caPath);
  if (ssl.passphrase) material.passphrase = ssl.passphrase;
  return material;
}

/**
 * Server options for node:https.
 *
 * TLS 1.2 is the floor and the cipher list is the modern set: anything older
 * would be a downgrade from what browsers already negotiate by default.
 */
export function tlsOptions(ssl = config.ssl) {
  return {
    ...readTlsMaterial(ssl),
    minVersion: ssl.minVersion,
    honorCipherOrder: true,
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
  };
}

/** Human-readable summary of the certificate in use, for the startup banner. */
export function describeCertificate(ssl = config.ssl) {
  try {
    const cert = new crypto.X509Certificate(fs.readFileSync(ssl.certPath));
    return {
      subject: cert.subject.replace(/\n/g, ', '),
      issuer: cert.issuer.replace(/\n/g, ', '),
      selfSigned: cert.subject === cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      expiresInDays: Math.round((new Date(cert.validTo).getTime() - Date.now()) / 86_400_000),
      altNames: cert.subjectAltName ?? null,
      fingerprint: cert.fingerprint256,
    };
  } catch (error) {
    return { error: error.message };
  }
}

/**
 * Every request gets bounced to the HTTPS listener.
 *
 * The Host header is attacker-controlled, so only the characters a hostname or
 * bracketed IPv6 literal may contain survive; anything else falls back to the
 * configured host rather than becoming an open redirect.
 */
export function httpsRedirectHandler(getHttpsPort, { publicHost = null } = {}) {
  return (req, res) => {
    const raw = String(req.headers.host ?? '');
    const hostOnly = raw.startsWith('[') ? raw.slice(0, raw.indexOf(']') + 1) : raw.split(':')[0];
    const safeHost = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+)$/.test(hostOnly) ? hostOnly : publicHost;

    if (!safeHost) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Bad host header\n');
      return;
    }

    const port = getHttpsPort();
    const authority = port === 443 ? safeHost : `${safeHost}:${port}`;
    // 308 keeps the method and body, so a POST that arrives on the HTTP port
    // is not silently turned into a GET.
    res.writeHead(308, {
      Location: `https://${authority}${req.url ?? '/'}`,
      'Cache-Control': 'no-store',
    });
    res.end();
  };
}
