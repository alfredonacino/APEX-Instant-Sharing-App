#!/usr/bin/env node
/**
 * Generate a self-signed TLS certificate for this app.
 *
 *   node scripts/generate-cert.js                 # create if missing
 *   node scripts/generate-cert.js --force         # replace an existing one
 *   node scripts/generate-cert.js --hosts files.example.lan --ips 10.0.0.5
 *   node scripts/generate-cert.js --days 397
 *
 * Every name the server answers to goes into subjectAltName, because browsers
 * ignore the legacy CN and will refuse a certificate that lacks a matching
 * SAN entry - including for a bare IP address.
 *
 * A self-signed certificate encrypts the traffic but proves nothing about who
 * is on the other end, so browsers warn until it is trusted explicitly. For a
 * certificate that is trusted out of the box, point SSL_KEY_PATH and
 * SSL_CERT_PATH at one from a real CA (Let's Encrypt, or your internal PKI).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { config } from '../src/config.js';

const { values } = parseArgs({
  options: {
    force: { type: 'boolean', default: false },
    'if-missing': { type: 'boolean', default: false },
    days: { type: 'string', default: '825' },
    hosts: { type: 'string' },
    ips: { type: 'string' },
    cn: { type: 'string' },
    help: { type: 'boolean', default: false },
  },
});

if (values.help) {
  console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').split('*/')[0].replace(/^\/\*\*|^ \* ?/gm, ''));
  process.exit(0);
}

const { keyPath, certPath, certDir } = config.ssl;

if (fs.existsSync(keyPath) && fs.existsSync(certPath) && !values.force) {
  if (values['if-missing']) {
    console.log(`certificate already present at ${certPath} - leaving it alone`);
    process.exit(0);
  }
  console.error(`A certificate already exists:\n  ${certPath}\nUse --force to replace it.`);
  process.exit(1);
}

try {
  execFileSync('openssl', ['version'], { stdio: 'pipe' });
} catch {
  console.error('openssl is required to generate a certificate but was not found on PATH.');
  process.exit(1);
}

// Collect every name and address this host can reasonably be reached by.
const hosts = new Set(['localhost', os.hostname()]);
const ips = new Set(['127.0.0.1', '::1']);

for (const addresses of Object.values(os.networkInterfaces())) {
  for (const address of addresses ?? []) {
    if (!address.internal && address.family === 'IPv4') ips.add(address.address);
  }
}
for (const host of (values.hosts ?? '').split(',').map((h) => h.trim()).filter(Boolean)) hosts.add(host);
for (const ip of (values.ips ?? '').split(',').map((i) => i.trim()).filter(Boolean)) ips.add(ip);

const commonName = values.cn || os.hostname();
const san = [...[...hosts].map((h) => `DNS:${h}`), ...[...ips].map((i) => `IP:${i}`)].join(',');

fs.mkdirSync(certDir, { recursive: true });

console.log(`Generating a self-signed certificate valid for ${values.days} days`);
console.log(`  CN  : ${commonName}`);
console.log(`  SANs: ${san}`);

execFileSync('openssl', [
  'req', '-x509',
  '-newkey', 'rsa:2048',
  '-sha256',
  '-nodes',
  '-days', String(values.days),
  '-keyout', keyPath,
  '-out', certPath,
  '-subj', `/CN=${commonName}/O=${config.appName}`,
  '-addext', `subjectAltName=${san}`,
  '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
  '-addext', 'extendedKeyUsage=serverAuth',
  '-addext', 'basicConstraints=critical,CA:FALSE',
], { stdio: ['ignore', 'ignore', 'inherit'] });

fs.chmodSync(keyPath, 0o600);
fs.chmodSync(certPath, 0o644);

const cert = new crypto.X509Certificate(fs.readFileSync(certPath));
console.log(`\nWrote ${path.relative(process.cwd(), certPath)} and ${path.relative(process.cwd(), keyPath)} (key mode 600)`);
console.log(`  valid until : ${cert.validTo}`);
console.log(`  SHA-256     : ${cert.fingerprint256}`);
console.log(`\nSet SSL_ENABLED=true (or just restart - a present key pair enables TLS by default).`);
console.log('Browsers will warn about this certificate until it is trusted; compare the');
console.log('fingerprint above before accepting it.');
