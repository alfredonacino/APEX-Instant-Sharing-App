import test from 'node:test';
import assert from 'node:assert/strict';
import { generate } from 'otplib';
import { prepareEnv, makeClient } from './helpers.js';

prepareEnv();

const { createApp } = await import('../server.js');
const { db } = await import('../src/lib/db.js');
const { verifyAuditChain } = await import('../src/lib/audit.js');

const server = createApp().listen(0);
await new Promise((resolve) => server.once('listening', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

const auditActions = (filter) =>
  db.prepare('SELECT action, outcome, object_label, details FROM audit_log ORDER BY id').all()
    .filter((row) => (filter ? row.action === filter : true));

/** Register, enrol TOTP and end up fully signed in. Returns the client + secret. */
async function newUser({ email, name, password = 'correct horse battery staple' }) {
  const client = makeClient(baseUrl);
  await client.get('/api/auth/session', { expect: 200 });

  const registered = await client.post('/api/auth/register', { email, displayName: name, password }, { expect: 201 });
  assert.equal(registered.body.stage, 'mfa_setup', 'a new account must enrol MFA before it is usable');

  const setup = await client.post('/api/auth/mfa/setup', {}, { expect: 200 });
  assert.match(setup.body.otpauthUri, /^otpauth:\/\/totp\//);
  assert.match(setup.body.qrDataUrl, /^data:image\/png;base64,/);

  const secret = setup.body.secret;
  const enabled = await client.post('/api/auth/mfa/enable', { token: await generate({ secret }) }, { expect: 200 });
  assert.equal(enabled.body.stage, 'authenticated');
  assert.equal(enabled.body.backupCodes.length, 10);

  return { client, secret, password, email, user: enabled.body.user, backupCodes: enabled.body.backupCodes };
}

/**
 * TOTP codes are one-time by design, and enrolment burns the current step.
 * Wait for the next 30-second window before signing in with the same secret.
 */
async function nextTotpStep() {
  await new Promise((resolve) => setTimeout(resolve, 30_000 - (Date.now() % 30_000) + 750));
}

async function upload(client, { name, content, visibility = 'private', shareWith = [], description = '', expiresAt }) {
  const form = new FormData();
  form.append('files', new Blob([content], { type: 'text/plain' }), name);
  form.append('visibility', visibility);
  form.append('description', description);
  if (shareWith.length) form.append('shareWith', shareWith.join(','));
  if (expiresAt) form.append('expiresAt', expiresAt);
  const result = await client.raw('POST', '/api/files', { form, expect: 201 });
  return result.body.files[0];
}

// --------------------------------------------------------------------------

let alice; let bob; let carol;

test('the first account becomes an administrator and must enrol MFA', async () => {
  alice = await newUser({ email: 'alice@example.com', name: 'Alice Admin' });
  assert.equal(alice.user.role, 'admin');
  assert.equal(alice.user.mfaEnabled, true);
});

test('subsequent accounts are ordinary users', async () => {
  bob = await newUser({ email: 'bob@example.com', name: 'Bob Builder' });
  carol = await newUser({ email: 'carol@example.com', name: 'Carol Coder' });
  assert.equal(bob.user.role, 'user');
  assert.equal(carol.user.role, 'user');
});

test('an unauthenticated caller cannot reach the API', async () => {
  const stranger = makeClient(baseUrl);
  await stranger.get('/api/auth/session', { expect: 200 });
  const files = await stranger.get('/api/files');
  assert.equal(files.status, 401);
  const admin = await stranger.get('/api/admin/users');
  assert.equal(admin.status, 401);
});

test('a state-changing request without the CSRF header is rejected', async () => {
  const result = await bob.client.raw('POST', '/api/auth/logout', { headers: { 'x-csrf-token': 'wrong-token' } });
  assert.equal(result.status, 403);
  assert.equal(result.body.code, 'csrf');
});

test('sign-in requires the second factor, and a code cannot be replayed', async () => {
  const client = makeClient(baseUrl);
  await client.get('/api/auth/session');

  const login = await client.post('/api/auth/login', { email: 'bob@example.com', password: bob.password }, { expect: 200 });
  assert.equal(login.body.authenticated, false);
  assert.equal(login.body.stage, 'mfa_required');

  // Password alone gets you nothing.
  assert.equal((await client.get('/api/files')).status, 401);

  assert.equal((await client.post('/api/auth/mfa/verify', { token: '000000' })).status, 401);

  await nextTotpStep();
  const token = await generate({ secret: bob.secret });
  const verified = await client.post('/api/auth/mfa/verify', { token }, { expect: 200 });
  assert.equal(verified.body.authenticated, true);

  // Same code, fresh sign-in: must be refused as a replay.
  const replayer = makeClient(baseUrl);
  await replayer.get('/api/auth/session');
  await replayer.post('/api/auth/login', { email: 'bob@example.com', password: bob.password }, { expect: 200 });
  const replay = await replayer.post('/api/auth/mfa/verify', { token });
  assert.equal(replay.status, 401);
  assert.match(replay.body.error, /already been used|not valid/);
});

test('a wrong password does not reveal whether the account exists', async () => {
  const client = makeClient(baseUrl);
  await client.get('/api/auth/session');
  const unknown = await client.post('/api/auth/login', { email: 'nobody@example.com', password: 'whatever-long-pass' });
  const known = await client.post('/api/auth/login', { email: 'carol@example.com', password: 'wrong-password-here' });
  assert.equal(unknown.status, 401);
  assert.equal(known.status, 401);
  assert.equal(unknown.body.error, known.body.error);
});

test('repeated failures lock the account, and an administrator can unlock it', async () => {
  const victim = await newUser({ email: 'dave@example.com', name: 'Dave Doomed' });
  const attacker = makeClient(baseUrl);
  await attacker.get('/api/auth/session');

  let locked = false;
  for (let i = 0; i < 5; i += 1) {
    const attempt = await attacker.post('/api/auth/login', { email: 'dave@example.com', password: 'not-the-password' });
    if (attempt.status === 423) locked = true;
  }
  assert.ok(locked, 'the account should lock after the configured number of failures');

  const blocked = await attacker.post('/api/auth/login', { email: 'dave@example.com', password: victim.password });
  assert.equal(blocked.status, 423);

  await alice.client.post(`/api/admin/users/${victim.user.id}/unlock`, {}, { expect: 200 });
  const after = await attacker.post('/api/auth/login', { email: 'dave@example.com', password: victim.password }, { expect: 200 });
  assert.equal(after.body.stage, 'mfa_required');
});

test('a backup code signs you in once and only once', async () => {
  const code = carol.backupCodes[0];
  const client = makeClient(baseUrl);
  await client.get('/api/auth/session');
  await client.post('/api/auth/login', { email: 'carol@example.com', password: carol.password }, { expect: 200 });
  const used = await client.post('/api/auth/mfa/verify', { backupCode: code }, { expect: 200 });
  assert.equal(used.body.authenticated, true);
  assert.equal(used.body.backupCodesRemaining, 9);

  const reuse = makeClient(baseUrl);
  await reuse.get('/api/auth/session');
  await reuse.post('/api/auth/login', { email: 'carol@example.com', password: carol.password }, { expect: 200 });
  assert.equal((await reuse.post('/api/auth/mfa/verify', { backupCode: code })).status, 401);
});

// ------------------------------------------------------------------ files --

let sharedFile;

test('a private upload is visible only to its recipients', async () => {
  sharedFile = await upload(bob.client, {
    name: 'quarterly-plan.txt',
    content: 'top secret plan',
    shareWith: [carol.user.id],
    description: 'For Carol only',
  });
  assert.equal(sharedFile.visibility, 'private');
  assert.equal(sharedFile.shareCount, 1);

  const carolList = await carol.client.get('/api/files?scope=shared', { expect: 200 });
  assert.ok(carolList.body.files.some((f) => f.id === sharedFile.id));

  const download = await carol.client.get(`/api/files/${sharedFile.id}/download`, { expect: 200 });
  assert.equal(download.buffer.toString(), 'top secret plan');
  assert.match(download.headers.get('content-disposition'), /attachment/);

  // A signed-in member with no grant must not even learn that the file exists.
  const bystander = await newUser({ email: 'gus@example.com', name: 'Gus Guest' });
  assert.equal((await bystander.client.get(`/api/files/${sharedFile.id}`)).status, 404);
  assert.equal((await bystander.client.get(`/api/files/${sharedFile.id}/download`)).status, 404);
  const bystanderList = await bystander.client.get('/api/files?scope=all', { expect: 200 });
  assert.ok(!bystanderList.body.files.some((f) => f.id === sharedFile.id));

  assert.equal((await carol.client.get('/api/files/fil_does_not_exist/download')).status, 404);
});

test('a file shared with everyone is downloadable by any signed-in account', async () => {
  const file = await upload(bob.client, { name: 'handbook.txt', content: 'company handbook', visibility: 'everyone' });
  const list = await carol.client.get('/api/files?scope=everyone', { expect: 200 });
  assert.ok(list.body.files.some((f) => f.id === file.id));
  const download = await carol.client.get(`/api/files/${file.id}/download`, { expect: 200 });
  assert.equal(download.buffer.toString(), 'company handbook');
});

test('revoking a share removes access immediately', async () => {
  await bob.client.del(`/api/files/${sharedFile.id}/shares/${carol.user.id}`, { expect: 200 });
  const denied = await carol.client.get(`/api/files/${sharedFile.id}/download`);
  assert.equal(denied.status, 404);
  const list = await carol.client.get('/api/files?scope=shared', { expect: 200 });
  assert.ok(!list.body.files.some((f) => f.id === sharedFile.id));
});

test('a share that has expired no longer grants access', async () => {
  const file = await upload(bob.client, {
    name: 'time-limited.txt',
    content: 'expires shortly',
    shareWith: [carol.user.id],
    expiresAt: new Date(Date.now() - 1000).toISOString(),
  });
  const denied = await carol.client.get(`/api/files/${file.id}/download`);
  assert.equal(denied.status, 404);
  // The owner still has it.
  await bob.client.get(`/api/files/${file.id}/download`, { expect: 200 });
});

test('one member cannot manage or delete another member file', async () => {
  const file = await upload(bob.client, { name: 'bobs-notes.txt', content: 'mine', visibility: 'everyone' });
  assert.equal((await carol.client.del(`/api/files/${file.id}`)).status, 404);
  assert.equal((await carol.client.patch(`/api/files/${file.id}`, { visibility: 'private' })).status, 404);
  await bob.client.get(`/api/files/${file.id}/download`, { expect: 200 });
});

test('an administrator sees every file but cannot download without a grant', async () => {
  const secret = await upload(bob.client, { name: 'private-to-bob.txt', content: 'bob only', shareWith: [carol.user.id] });
  const adminList = await alice.client.get('/api/files?scope=admin', { expect: 200 });
  assert.ok(adminList.body.files.some((f) => f.id === secret.id), 'admin file browser lists every file');

  const blocked = await alice.client.get(`/api/files/${secret.id}/download`);
  assert.equal(blocked.status, 403, 'ADMIN_CAN_DOWNLOAD_ALL=false must block the download');

  const denials = auditActions('file.download').filter((e) => e.outcome === 'denied');
  assert.ok(denials.length > 0, 'the refused administrator download is on the record');
});

test('uploaded filenames are stripped of directory components', async () => {
  const file = await upload(bob.client, { name: '../../etc/passwd', content: 'not really passwd', visibility: 'everyone' });
  assert.equal(file.name, 'passwd');
});

test('deleting a file removes it from every listing', async () => {
  const file = await upload(bob.client, { name: 'temporary.txt', content: 'bye', visibility: 'everyone' });
  await bob.client.del(`/api/files/${file.id}`, { expect: 200 });
  assert.equal((await carol.client.get(`/api/files/${file.id}/download`)).status, 404);
  const list = await bob.client.get('/api/files?scope=mine', { expect: 200 });
  assert.ok(!list.body.files.some((f) => f.id === file.id));
});

test('an upload larger than the limit is refused', async () => {
  const form = new FormData();
  form.append('files', new Blob([Buffer.alloc(6 * 1024 * 1024)]), 'too-big.bin');
  form.append('visibility', 'everyone');
  const result = await bob.client.raw('POST', '/api/files', { form });
  assert.equal(result.status, 413);
});

// ------------------------------------------------------------------ admin --

test('a regular user cannot reach the administrator endpoints', async () => {
  assert.equal((await bob.client.get('/api/admin/users')).status, 403);
  assert.equal((await bob.client.get('/api/admin/audit')).status, 403);
  assert.equal((await bob.client.patch(`/api/admin/users/${carol.user.id}`, { role: 'admin' })).status, 403);
});

test('an administrator can disable an account, which ends its sessions', async () => {
  const target = await newUser({ email: 'erin@example.com', name: 'Erin Exit' });
  await target.client.get('/api/files', { expect: 200 });

  await alice.client.patch(`/api/admin/users/${target.user.id}`, { status: 'disabled' }, { expect: 200 });
  assert.equal((await target.client.get('/api/files')).status, 401);

  const login = await makeClient(baseUrl);
  await login.get('/api/auth/session');
  assert.equal((await login.post('/api/auth/login', { email: 'erin@example.com', password: target.password })).status, 403);
});

test('the last administrator cannot be demoted', async () => {
  const result = await alice.client.patch(`/api/admin/users/${alice.user.id}`, { role: 'user' });
  assert.equal(result.status, 409);
});

test('an administrator can clear a lost authenticator, forcing re-enrolment', async () => {
  const target = await newUser({ email: 'frank@example.com', name: 'Frank Forgot' });
  await alice.client.post(`/api/admin/users/${target.user.id}/mfa/reset`, { reason: 'lost phone, verified by video call' }, { expect: 200 });

  const client = makeClient(baseUrl);
  await client.get('/api/auth/session');
  const login = await client.post('/api/auth/login', { email: 'frank@example.com', password: target.password }, { expect: 200 });
  assert.equal(login.body.stage, 'mfa_setup', 'the account must enrol a new authenticator');
  assert.equal((await client.get('/api/files')).status, 401);

  const reasons = auditActions('mfa.reset');
  assert.equal(JSON.parse(reasons.at(-1).details).reason, 'lost phone, verified by video call');
});

// ------------------------------------------------------------------ audit --

test('every meaningful action lands in the audit trail', async () => {
  const actions = new Set(auditActions().map((e) => e.action));
  for (const expected of [
    'auth.register', 'auth.login', 'auth.login.mfa', 'auth.login.backup_code', 'mfa.enable', 'mfa.reset',
    'file.upload', 'file.download', 'file.delete', 'share.grant', 'share.revoke', 'share.visibility',
    'admin.user.update', 'account.lock', 'account.unlock', 'security.csrf_rejected',
  ]) {
    assert.ok(actions.has(expected), `expected an audit entry for ${expected}`);
  }

  const downloads = auditActions('file.download').filter((e) => e.outcome === 'success');
  assert.ok(downloads.some((d) => d.object_label === 'quarterly-plan.txt'), 'downloads name the file');
});

test('the audit trail is append-only at the database level', async () => {
  assert.throws(() => db.exec("UPDATE audit_log SET action = 'nope' WHERE id = 1"), /append-only/);
  assert.throws(() => db.exec('DELETE FROM audit_log WHERE id = 1'), /append-only/);
});

test('the hash chain verifies, and detects a row edited behind the app back', async () => {
  const before = await alice.client.get('/api/admin/audit/verify', { expect: 200 });
  assert.equal(before.body.ok, true);
  assert.ok(before.body.entries > 20);

  // Simulate a database-level attacker: drop the guard trigger, edit a row, restore it.
  db.exec('DROP TRIGGER audit_log_no_update');
  db.exec("UPDATE audit_log SET action = 'file.list' WHERE id = (SELECT MIN(id) FROM audit_log WHERE action = 'file.download')");
  db.exec(`CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
           BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END`);

  const after = verifyAuditChain();
  assert.equal(after.ok, false);
  assert.match(after.reason, /do not match/);
});

test('a member sees their own activity and nobody else', async () => {
  const mine = await carol.client.get('/api/users/me/activity?limit=200', { expect: 200 });
  assert.ok(mine.body.entries.length > 0);
  const foreign = mine.body.entries.filter((e) => e.action === 'auth.login' && e.details?.email && e.details.email !== 'carol@example.com');
  assert.equal(foreign.length, 0);
});
