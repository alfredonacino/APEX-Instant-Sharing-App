/**
 * Public links, and the administrator's control over account creation.
 *
 * Both features change who can reach the app, so the checks here are about the
 * boundary: what an anonymous caller can and cannot do, and that a switch thrown
 * in the admin screen actually takes effect and is recorded.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generate } from 'otplib';
import { prepareEnv, makeClient } from './helpers.js';

prepareEnv();

const { createApp } = await import('../src/app.js');
const { db } = await import('../src/lib/db.js');
const { getSetting } = await import('../src/services/settings.service.js');
const { verifyAuditChain } = await import('../src/lib/audit.js');

const server = createApp().listen(0);
await new Promise((resolve) => server.once('listening', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

const audits = (action) =>
  db.prepare('SELECT action, outcome, object_label, details FROM audit_log ORDER BY id').all()
    .filter((row) => (action ? row.action === action : true))
    .map((row) => ({ ...row, details: JSON.parse(row.details) }));

/** Register and enrol TOTP, ending fully signed in. No sign-in, so no TOTP wait. */
async function newUser({ email, name, password = 'correct horse battery staple' }) {
  const client = makeClient(baseUrl);
  await client.get('/api/auth/session', { expect: 200 });
  await client.post('/api/auth/register', { email, displayName: name, password }, { expect: 201 });
  const setup = await client.post('/api/auth/mfa/setup', {}, { expect: 200 });
  const enabled = await client.post(
    '/api/auth/mfa/enable',
    { token: await generate({ secret: setup.body.secret }) },
    { expect: 200 },
  );
  return { client, user: enabled.body.user };
}

async function upload(client, { name, content, visibility = 'private' }) {
  const form = new FormData();
  form.append('files', new Blob([content], { type: 'text/plain' }), name);
  form.append('visibility', visibility);
  const result = await client.raw('POST', '/api/files', { form, expect: 201 });
  return result.body.files[0];
}

// The first account registered becomes the administrator.
const admin = await newUser({ email: 'admin@example.com', name: 'Ada Admin' });
const member = await newUser({ email: 'member@example.com', name: 'Mo Member' });

// An anonymous visitor: a client that never authenticates.
const anon = () => makeClient(baseUrl);

// ------------------------------------------------------------ public links --

test('a public link lets someone with no account download one file', async () => {
  const file = await upload(member.client, { name: 'report.txt', content: 'quarterly numbers' });

  // Without a link, an anonymous caller has no way in at all.
  const blocked = await anon().get(`/api/files/${file.id}/download`);
  assert.equal(blocked.status, 401, 'an anonymous caller must not reach the authenticated download route');

  const created = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  const { token, url } = created.body.publicLink;
  assert.match(token, /^[A-Za-z0-9_-]{20,}$/, 'the token must be long and URL-safe');
  assert.match(url, /\/p\//, 'the owner is handed a shareable URL');

  const visitor = anon();
  const meta = await visitor.get(`/api/public/${token}`, { expect: 200 });
  assert.equal(meta.body.file.name, 'report.txt');
  assert.equal(meta.body.file.size, 'quarterly numbers'.length);
  assert.equal(meta.body.sharedBy, 'Mo Member', 'the recipient sees who shared it');
  assert.equal(meta.body.file.sha256.length, 64);
  // Minimal disclosure: no account details reach an anonymous caller.
  assert.equal(JSON.stringify(meta.body).includes('member@example.com'), false);

  const download = await visitor.get(`/api/public/${token}/download`, { expect: 200 });
  assert.equal(download.buffer.toString(), 'quarterly numbers');
  assert.match(download.headers.get('content-disposition'), /attachment/);
  assert.match(download.headers.get('content-disposition'), /report\.txt/);
  assert.equal(download.headers.get('x-content-type-options'), 'nosniff');
});

test('an anonymous download is audited as such, and counted', async () => {
  const file = await upload(member.client, { name: 'counted.txt', content: 'abc' });
  const { body } = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  await anon().get(`/api/public/${body.publicLink.token}/download`, { expect: 200 });

  const entry = audits('share.link.download').at(-1);
  assert.equal(entry.outcome, 'success');
  assert.equal(entry.object_label, 'counted.txt');
  assert.equal(entry.details.via, 'public_link');
  assert.equal(entry.details.anonymous, true);
  assert.equal(entry.details.tokenPrefix.length, 8, 'only a prefix of the capability is logged');
  assert.equal(
    JSON.stringify(entry.details).includes(body.publicLink.token),
    false,
    'the full token must never be written to the audit log',
  );

  const detail = await member.client.get(`/api/files/${file.id}`, { expect: 200 });
  assert.equal(detail.body.publicLink.downloadCount, 1);
  assert.equal(detail.body.file.downloadCount, 1, 'the file total counts link downloads too');
});

test('revoking a link turns it off immediately', async () => {
  const file = await upload(member.client, { name: 'revoke-me.txt', content: 'secret' });
  const { body } = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  const { token } = body.publicLink;

  await anon().get(`/api/public/${token}`, { expect: 200 });
  await member.client.del(`/api/files/${file.id}/link`, { expect: 200 });

  const after = await anon().get(`/api/public/${token}`);
  assert.equal(after.status, 410, 'a revoked link is gone, not merely missing');
  assert.equal(after.body.code, 'link_revoked');
  await anon().get(`/api/public/${token}/download`, { expect: 410 });

  const detail = await member.client.get(`/api/files/${file.id}`, { expect: 200 });
  assert.equal(detail.body.publicLink, null);
});

test('creating a link again rotates it, and the old token stops working', async () => {
  const file = await upload(member.client, { name: 'rotate.txt', content: 'data' });
  const first = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  const second = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });

  assert.notEqual(first.body.publicLink.token, second.body.publicLink.token);
  await anon().get(`/api/public/${first.body.publicLink.token}`, { expect: 410 });
  await anon().get(`/api/public/${second.body.publicLink.token}`, { expect: 200 });

  assert.equal(audits('share.link.create').at(-1).details.rotated, true);
});

test('changing a link limit keeps the same URL', async () => {
  const file = await upload(member.client, { name: 'keep-url.txt', content: 'stable' });
  const created = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  const { token } = created.body.publicLink;

  const updated = await member.client.patch(
    `/api/files/${file.id}/link`,
    { maxDownloads: 5, expiresAt: new Date(Date.now() + 86_400_000).toISOString() },
    { expect: 200 },
  );
  assert.equal(updated.body.publicLink.token, token, 'adjusting a limit must not invalidate a URL already shared');
  assert.equal(updated.body.publicLink.maxDownloads, 5);

  const meta = await anon().get(`/api/public/${token}`, { expect: 200 });
  assert.equal(meta.body.downloadsRemaining, 5);
  assert.equal(audits('share.link.create').at(-1).details.rotated, false);

  // Clearing the limits is an explicit null, not a missing field.
  const cleared = await member.client.patch(
    `/api/files/${file.id}/link`,
    { maxDownloads: null, expiresAt: null },
    { expect: 200 },
  );
  assert.equal(cleared.body.publicLink.maxDownloads, null);
  assert.equal(cleared.body.publicLink.expiresAt, null);
  assert.equal(cleared.body.publicLink.token, token);
});

test('a link cannot be updated when there is none', async () => {
  const file = await upload(member.client, { name: 'nolink.txt', content: 'x' });
  assert.equal((await member.client.patch(`/api/files/${file.id}/link`, { maxDownloads: 3 })).status, 404);
});

test('an expired link is refused', async () => {
  const file = await upload(member.client, { name: 'expired.txt', content: 'old' });
  const { body } = await member.client.post(
    `/api/files/${file.id}/link`,
    { expiresAt: new Date(Date.now() - 60_000).toISOString() },
    { expect: 201 },
  );
  const result = await anon().get(`/api/public/${body.publicLink.token}`);
  assert.equal(result.status, 410);
  assert.equal(result.body.code, 'link_expired');
});

test('a download limit is enforced', async () => {
  const file = await upload(member.client, { name: 'capped.txt', content: 'once' });
  const { body } = await member.client.post(`/api/files/${file.id}/link`, { maxDownloads: 1 }, { expect: 201 });
  const { token } = body.publicLink;

  const meta = await anon().get(`/api/public/${token}`, { expect: 200 });
  assert.equal(meta.body.downloadsRemaining, 1);

  await anon().get(`/api/public/${token}/download`, { expect: 200 });
  const second = await anon().get(`/api/public/${token}/download`);
  assert.equal(second.status, 410);
  assert.equal(second.body.code, 'download_limit_reached');
});

test('an unknown token is a flat 404, and a malformed one never reaches the database', async () => {
  assert.equal((await anon().get('/api/public/AAAAAAAAAAAAAAAAAAAAAAAAAAAA')).status, 404);
  assert.equal((await anon().get('/api/public/short')).status, 404);
  assert.equal((await anon().get('/api/public/has%20spaces%20and%20punctuation!!')).status, 404);
});

test('only the owner or an administrator can mint a link for a file', async () => {
  const file = await upload(member.client, { name: 'mine.txt', content: 'mine' });
  const stranger = await newUser({ email: 'stranger@example.com', name: 'Sam Stranger' });

  // A stranger cannot even see the file, so the attempt is a 404, not a 403.
  assert.equal((await stranger.client.post(`/api/files/${file.id}/link`, {})).status, 404);

  // An administrator can, and the override is recorded.
  await admin.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  assert.equal(audits('share.link.create').at(-1).details.adminOverride, true);
});

test('a link to a deleted file stops working', async () => {
  const file = await upload(member.client, { name: 'doomed.txt', content: 'bye' });
  const { body } = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  await member.client.del(`/api/files/${file.id}`, { expect: 200 });

  const result = await anon().get(`/api/public/${body.publicLink.token}`);
  assert.equal(result.status, 410);
  assert.equal(result.body.code, 'file_deleted');
});

// ------------------------------------------- administrator-controlled policy --

test('an administrator can switch account creation off and on', async () => {
  const policy = await anon().get('/api/policy', { expect: 200 });
  assert.equal(policy.body.policy.allowSelfRegistration, true, 'the .env default applies until an admin decides');

  await admin.client.patch('/api/admin/settings', { allowSelfRegistration: false }, { expect: 200 });

  // The sign-in screen stops offering the option...
  const closed = await anon().get('/api/policy', { expect: 200 });
  assert.equal(closed.body.policy.allowSelfRegistration, false);

  // ...and the endpoint itself refuses, which is what actually matters.
  const walkIn = anon();
  await walkIn.get('/api/auth/session', { expect: 200 }); // seeds the CSRF cookie
  const refused = await walkIn.post('/api/auth/register', {
    email: 'walkin@example.com', displayName: 'Walk In', password: 'correct horse battery staple',
  });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.code, 'forbidden', 'refused by policy, not by CSRF');
  assert.equal(audits('auth.register').at(-1).details.reason, 'self_registration_disabled');

  // The decision is stored, so a restart would not quietly revert it.
  assert.equal(getSetting('allowSelfRegistration'), false);

  const entry = audits('admin.settings.update').at(-1);
  assert.equal(entry.details.setting, 'allowSelfRegistration');
  assert.equal(entry.details.from, true);
  assert.equal(entry.details.to, false);

  await admin.client.patch('/api/admin/settings', { allowSelfRegistration: true }, { expect: 200 });
  const reopened = await newUser({ email: 'later@example.com', name: 'Lee Later' });
  assert.equal(reopened.user.email, 'later@example.com');
});

test('a regular member cannot change policy', async () => {
  const attempt = await member.client.patch('/api/admin/settings', { allowSelfRegistration: false });
  assert.equal(attempt.status, 403);
  assert.equal(getSetting('allowSelfRegistration'), true, 'the setting is untouched');
});

test('turning public links off disables every existing link at once', async () => {
  const file = await upload(member.client, { name: 'global.txt', content: 'x' });
  const { body } = await member.client.post(`/api/files/${file.id}/link`, {}, { expect: 201 });
  const { token } = body.publicLink;
  await anon().get(`/api/public/${token}`, { expect: 200 });

  await admin.client.patch('/api/admin/settings', { allowPublicLinks: false }, { expect: 200 });

  const blocked = await anon().get(`/api/public/${token}`);
  assert.equal(blocked.status, 403, 'an existing link stops working, without being revoked');
  assert.equal(audits('share.link.download').at(-1).details.reason, 'public_links_disabled');

  // And no new link can be minted while the feature is off.
  const refused = await member.client.post(`/api/files/${file.id}/link`, {});
  assert.equal(refused.status, 403);

  const entry = audits('admin.settings.update').at(-1);
  assert.equal(entry.details.setting, 'allowPublicLinks');
  assert.equal(typeof entry.details.liveLinksDisabled, 'number');

  // Switching it back on brings the same token back to life.
  await admin.client.patch('/api/admin/settings', { allowPublicLinks: true }, { expect: 200 });
  await anon().get(`/api/public/${token}`, { expect: 200 });
});

test('settings validation rejects nonsense', async () => {
  assert.equal((await admin.client.patch('/api/admin/settings', {})).status, 400);
  assert.equal((await admin.client.patch('/api/admin/settings', { nope: true })).status, 400);
  assert.equal((await admin.client.patch('/api/admin/settings', { allowSelfRegistration: 'yes' })).status, 400);
});

test('the audit chain still verifies after all of this', () => {
  const result = verifyAuditChain();
  assert.equal(result.ok, true, result.reason ?? '');
});
