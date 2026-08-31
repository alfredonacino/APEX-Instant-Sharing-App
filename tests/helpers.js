import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

/** Isolated data/storage directories and deterministic policy for the suite. */
export function prepareEnv(overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'apex-test-'));
  Object.assign(process.env, {
    NODE_ENV: 'test',
    DATA_DIR: path.join(root, 'data'),
    STORAGE_DIR: path.join(root, 'blobs'),
    // Isolate TLS as well: a certificate sitting in the developer's ./certs
    // would otherwise switch this suite to Secure cookies over plain HTTP.
    CERT_DIR: path.join(root, 'certs'),
    SSL_ENABLED: 'false',
    APP_KEY: crypto.randomBytes(32).toString('hex'),
    SESSION_SECRET: crypto.randomBytes(32).toString('base64url'),
    REQUIRE_MFA: 'true',
    ALLOW_SELF_REGISTRATION: 'true',
    ADMIN_CAN_DOWNLOAD_ALL: 'false',
    MAX_UPLOAD_MB: '5',
    MAX_FAILED_LOGINS: '5',
    TRUST_PROXY: '0',
    ...overrides,
  });
  return root;
}

/** Minimal browser stand-in: keeps cookies and echoes the CSRF token. */
export function makeClient(baseUrl) {
  const jar = new Map();

  async function request(method, urlPath, { body, form, headers = {}, expect } = {}) {
    const outgoing = { accept: 'application/json', ...headers };
    if (jar.size) outgoing.cookie = [...jar].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; ');
    if (!['GET', 'HEAD'].includes(method) && jar.has('apex.csrf') && !('x-csrf-token' in outgoing)) {
      outgoing['x-csrf-token'] = jar.get('apex.csrf');
    }

    let payload;
    if (form) payload = form;
    else if (body !== undefined) {
      outgoing['content-type'] = 'application/json';
      payload = JSON.stringify(body);
    }

    const response = await fetch(new URL(urlPath, baseUrl), { method, headers: outgoing, body: payload, redirect: 'manual' });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx).trim();
      const value = decodeURIComponent(pair.slice(idx + 1).trim());
      if (/expires=thu, 01 jan 1970/i.test(cookie) || value === '') jar.delete(name);
      else jar.set(name, value);
    }

    const contentType = response.headers.get('content-type') ?? '';
    const isJson = contentType.includes('application/json');
    const result = {
      status: response.status,
      headers: response.headers,
      body: isJson ? await response.json() : null,
      buffer: isJson ? null : Buffer.from(await response.arrayBuffer()),
    };
    if (expect !== undefined && result.status !== expect) {
      throw new Error(`${method} ${urlPath} expected ${expect}, got ${result.status}: ${JSON.stringify(result.body ?? result.buffer?.slice(0, 120).toString())}`);
    }
    return result;
  }

  return {
    jar,
    get: (p, o) => request('GET', p, o),
    post: (p, body, o) => request('POST', p, { body, ...o }),
    patch: (p, body, o) => request('PATCH', p, { body, ...o }),
    del: (p, o) => request('DELETE', p, o),
    raw: request,
  };
}
