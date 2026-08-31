/* Administrator panels: user management and the audit trail. */
import { api, qs } from './api.js';
import { $, $$, clear, confirmAction, formatBytes, formatDate, h, setError, show, timeAgo, toast } from './ui.js';

const AUDIT_PAGE = 100;
const state = { me: null, auditOffset: 0, auditTotal: 0, userQuery: '' };

export function initAdmin({ user }) {
  state.me = user;

  let timer;
  $('#user-search').addEventListener('input', (event) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      state.userQuery = event.target.value.trim();
      loadUsers();
    }, 250);
  });

  $('#form-newuser').addEventListener('submit', createUser);

  for (const control of ['#audit-action', '#audit-outcome', '#audit-actor', '#audit-q', '#audit-from', '#audit-to']) {
    $(control).addEventListener('change', () => {
      state.auditOffset = 0;
      loadAudit();
    });
  }
  $('#audit-more').addEventListener('click', () => {
    state.auditOffset += AUDIT_PAGE;
    loadAudit({ append: true });
  });
  $('#audit-verify').addEventListener('click', verifyChain);
}

// ------------------------------------------------------------------ users --

export async function loadUsers() {
  await loadStats();
  const body = clear($('#users-table').tBodies[0]);
  try {
    const { users } = await api.get(`/api/admin/users?${qs({ q: state.userQuery })}`);
    for (const user of users) body.append(userRow(user));
  } catch (error) {
    body.append(h('tr', {}, h('td', { colspan: 7, class: 'error' }, error.message)));
  }
}

function userRow(user) {
  const isMe = user.id === state.me.id;

  const roleSelect = h('select', {
    onchange: (event) => updateUser(user, { role: event.target.value }),
  },
    h('option', { value: 'user', selected: user.role === 'user' }, 'User'),
    h('option', { value: 'admin', selected: user.role === 'admin' }, 'Administrator'));

  const actions = h('div', { class: 'row' },
    // Disabling yourself is refused by the server; do not offer the button.
    isMe ? null : h('button', {
      class: 'btn tiny', type: 'button',
      onclick: () => updateUser(user, { status: user.status === 'active' ? 'disabled' : 'active' }),
    }, user.status === 'active' ? 'Disable' : 'Enable'),
    user.locked ? h('button', { class: 'btn tiny', type: 'button', onclick: () => unlockUser(user) }, 'Unlock') : null,
    user.mfaEnabled ? h('button', { class: 'btn tiny danger', type: 'button', onclick: () => resetMfa(user) }, 'Reset 2FA') : null,
    h('button', { class: 'btn tiny', type: 'button', onclick: () => resetPassword(user) }, 'Set password'));

  return h('tr', {},
    h('td', {}, user.displayName, isMe ? h('span', { class: 'badge' }, 'you') : null),
    h('td', { class: 'muted' }, user.email),
    h('td', {}, isMe ? user.role : roleSelect),
    h('td', {}, h('span', { class: `outcome ${user.status === 'active' ? 'success' : 'failure'}` }, user.status),
      user.locked ? h('div', { class: 'muted small' }, `locked until ${formatDate(user.lockedUntil, { short: true })}`) : null),
    h('td', {}, user.mfaEnabled ? '✅ enrolled' : h('span', { class: 'muted' }, 'not enrolled')),
    h('td', { class: 'muted' }, user.lastLoginAt ? timeAgo(user.lastLoginAt) : 'never'),
    h('td', {}, actions));
}

async function updateUser(user, changes) {
  if (changes.status === 'disabled' && !confirmAction(`Disable ${user.displayName}? Their sessions end immediately.`)) {
    return loadUsers();
  }
  try {
    await api.patch(`/api/admin/users/${encodeURIComponent(user.id)}`, changes);
    toast(`${user.displayName} updated`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
  loadUsers();
}

async function unlockUser(user) {
  try {
    await api.post(`/api/admin/users/${encodeURIComponent(user.id)}/unlock`);
    toast(`${user.displayName} unlocked`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
  loadUsers();
}

async function resetMfa(user) {
  const reason = window.prompt(`Clear the authenticator for ${user.displayName}?\nRecord a reason for the audit trail:`);
  if (!reason) return;
  try {
    await api.post(`/api/admin/users/${encodeURIComponent(user.id)}/mfa/reset`, { reason });
    toast(`${user.displayName} must enrol a new authenticator at next sign-in`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
  loadUsers();
}

async function resetPassword(user) {
  const newPassword = window.prompt(`New password for ${user.displayName} (at least 12 characters):`);
  if (!newPassword) return;
  const reason = window.prompt('Reason for the audit trail:');
  if (!reason) return;
  try {
    await api.post(`/api/admin/users/${encodeURIComponent(user.id)}/password`, { newPassword, reason });
    toast('Password set - all their sessions were revoked', 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function createUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  setError(form, '');
  try {
    const values = Object.fromEntries(new FormData(form).entries());
    await api.post('/api/admin/users', values);
    toast(`Account created for ${values.email}`, 'success');
    form.reset();
    loadUsers();
  } catch (error) {
    setError(form, error.message);
  }
}

async function loadStats() {
  try {
    const { storage, audit, policy } = await api.get('/api/admin/stats');
    const box = clear($('#admin-stats'));
    const stat = (value, label) => h('div', { class: 'stat' }, h('b', {}, String(value)), h('span', {}, label));
    box.append(
      stat(storage.users.active, 'active users'),
      stat(`${storage.users.withMfa}/${storage.users.total}`, '2FA enrolled'),
      stat(storage.files, 'files stored'),
      stat(formatBytes(storage.bytes), 'on disk'),
      stat(storage.shares, 'direct shares'),
      stat(storage.sharedWithEveryone, 'shared with all'),
      stat(storage.downloads, 'downloads'),
      stat(audit.entries, `audit entries${audit.intact ? '' : ' ⚠'}`),
    );
    $('#audit-integrity').textContent = policy.requireMfa
      ? 'Policy: two-factor authentication is mandatory for every account.'
      : 'Policy: two-factor authentication is optional on this deployment.';
  } catch (error) {
    toast(error.message, 'error');
  }
}

// ------------------------------------------------------------------ audit --

function auditFilters() {
  return {
    action: $('#audit-action').value,
    outcome: $('#audit-outcome').value,
    actor: $('#audit-actor').value.trim(),
    q: $('#audit-q').value.trim(),
    from: $('#audit-from').value ? new Date($('#audit-from').value).toISOString() : '',
    to: $('#audit-to').value ? new Date(`${$('#audit-to').value}T23:59:59`).toISOString() : '',
  };
}

export async function loadAudit({ append = false } = {}) {
  const table = $('#audit-table');
  const body = table.tBodies[0];
  if (!append) clear(body);

  try {
    const filters = auditFilters();
    const result = await api.get(`/api/admin/audit?${qs({ ...filters, limit: AUDIT_PAGE, offset: state.auditOffset })}`);
    state.auditTotal = result.total;

    const select = $('#audit-action');
    if (select.options.length <= 1) {
      for (const action of result.actions) select.append(h('option', { value: action }, action));
      select.value = filters.action;
    }

    if (result.entries.length === 0 && !append) {
      body.append(h('tr', {}, h('td', { colspan: 7, class: 'muted' }, 'No entries match those filters.')));
    }
    for (const entry of result.entries) body.append(auditRow(entry));

    show($('#audit-more'), state.auditOffset + result.entries.length < result.total);
    $('#audit-export').href = `/api/admin/audit.csv?${qs(filters)}`;
  } catch (error) {
    body.append(h('tr', {}, h('td', { colspan: 7, class: 'error' }, error.message)));
  }
}

function auditRow(entry) {
  const details = Object.entries(entry.details ?? {})
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join(' ');
  return h('tr', {},
    h('td', { class: 'muted small', title: entry.ts }, formatDate(entry.ts, { short: true })),
    h('td', {}, entry.actor_email ?? h('span', { class: 'muted' }, 'anonymous')),
    h('td', {}, entry.action),
    h('td', {}, h('span', { class: `outcome ${entry.outcome}` }, entry.outcome)),
    h('td', {}, entry.object_label ?? entry.object_id ?? '-'),
    h('td', { class: 'muted small' }, entry.ip ?? '-'),
    h('td', { class: 'details' }, details));
}

async function verifyChain() {
  const slot = $('#audit-integrity');
  slot.textContent = 'Verifying...';
  slot.className = 'integrity';
  try {
    const result = await api.get('/api/admin/audit/verify');
    slot.className = `integrity ${result.ok ? 'ok' : 'bad'}`;
    slot.textContent = result.ok
      ? `✔ Chain intact across ${result.entries} entries (head ${String(result.head).slice(0, 16)}...).`
      : `✘ Tampering detected at entry ${result.brokenAt}: ${result.reason}`;
  } catch (error) {
    slot.className = 'integrity bad';
    slot.textContent = error.message;
  }
}
