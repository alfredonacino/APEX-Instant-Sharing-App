import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { prepareEnv } from './helpers.js';

const root = prepareEnv();
const certDir = path.join(root, 'certs');
process.env.CERT_DIR = certDir;
process.env.SSL_ENABLED = 'true';

let opensslAvailable = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'pipe' });
} catch {
  opensslAvailable = false;
}

// The certificate has to exist before config.js is imported: TLS settings are
// resolved once, at import time.
if (opensslAvailable) {
  fs.mkdirSync(certDir, { recursive: true });
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '2',
    '-keyout', path.join(certDir, 'server.key'),
    '-out', path.join(certDir, 'server.crt'),
    '-subj', '/CN=localhost/O=apex-test',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
}

const suite = opensslAvailable ? test : test.skip;

/** Minimal HTTPS client that trusts exactly the certificate under test. */
function httpsGet(port, urlPath, { ca, servername = 'localhost' } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port, path: urlPath, method: 'GET', ca, servername },
      (res) => {
        // The socket is detached once the response completes, so the TLS
        // details have to be read while it is still attached.
        const tls = {
          protocol: res.socket.getProtocol(),
          cipher: res.socket.getCipher()?.name ?? null,
          peerCertificate: res.socket.getPeerCertificate(),
        };
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body, tls }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

function httpGet(port, urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: urlPath, method: 'GET' }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

suite('TLS: the app serves HTTPS and redirects plain HTTP to it', async (t) => {
  const { config } = await import('../src/config.js');
  const { start } = await import('../src/runtime.js');

  assert.equal(config.ssl.enabled, true, 'a present key pair should enable TLS');
  assert.equal(config.cookieSecure, true, 'cookies must be marked Secure once TLS is on');

  const runtime = await start({ port: 0, httpsPort: 0 });
  t.after(() => runtime.close());

  const ca = fs.readFileSync(config.ssl.certPath);

  await t.test('serves the API over TLS', async () => {
    const res = await httpsGet(runtime.httpsPort, '/healthz', { ca });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).ok, true);
  });

  await t.test('negotiates TLS 1.2 or better', async () => {
    const res = await httpsGet(runtime.httpsPort, '/healthz', { ca });
    const protocol = res.tls.protocol;
    assert.ok(['TLSv1.2', 'TLSv1.3'].includes(protocol), `unexpected protocol ${protocol}`);
  });

  await t.test('sends HSTS and marks cookies Secure', async () => {
    const res = await httpsGet(runtime.httpsPort, '/api/policy', { ca });
    assert.match(res.headers['strict-transport-security'] ?? '', /max-age=\d+/);
    const cookies = res.headers['set-cookie'] ?? [];
    const csrf = cookies.find((c) => c.startsWith('apex.csrf='));
    assert.ok(csrf, 'the CSRF cookie should be set');
    assert.match(csrf, /Secure/);
  });

  await t.test('redirects plain HTTP to HTTPS, preserving path and method semantics', async () => {
    const res = await httpGet(runtime.httpPort, '/api/files?scope=mine');
    assert.equal(res.status, 308, '308 keeps a POST a POST');
    assert.equal(res.headers.location, `https://127.0.0.1:${runtime.httpsPort}/api/files?scope=mine`);
  });

  await t.test('refuses to build a redirect from a junk Host header', async () => {
    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: runtime.httpPort, path: '/', method: 'GET', headers: { Host: 'evil.example.com/@attacker' } },
        (r) => { r.resume(); resolve({ status: r.statusCode, headers: r.headers }); },
      );
      req.on('error', reject);
      req.end();
    });
    assert.equal(res.status, 400);
    assert.equal(res.headers.location, undefined);
  });

  await t.test('reloads a renewed certificate without a restart', async () => {
    const before = new crypto.X509Certificate(fs.readFileSync(config.ssl.certPath)).serialNumber;

    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '3',
      '-keyout', config.ssl.keyPath, '-out', config.ssl.certPath,
      '-subj', '/CN=localhost/O=apex-test-renewed',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], { stdio: ['ignore', 'ignore', 'pipe'] });

    assert.equal(runtime.reloadCertificate(), true);

    const renewed = fs.readFileSync(config.ssl.certPath);
    const after = new crypto.X509Certificate(renewed).serialNumber;
    assert.notEqual(before, after, 'the test should have produced a different certificate');

    // A new handshake must present the renewed certificate.
    const res = await httpsGet(runtime.httpsPort, '/healthz', { ca: renewed });
    assert.equal(res.status, 200);
    assert.equal(res.tls.peerCertificate.serialNumber, after);
  });
});
