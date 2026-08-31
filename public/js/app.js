/* Bootstrap: resolve the session, wire navigation, own the account panel. */
import { api } from './api.js';
import { $, $$, clear, formatDate, h, setError, show, timeAgo, toast } from './ui.js';
import { initAuth, routeSession, showScreen, signOut, startEnrolment, showBackupCodes, submitHandler } from './auth.js';
import { initFiles, loadFiles, setUser } from './files.js';
import { initAdmin, loadAudit, loadUsers } from './admin.js';

const app = { session: null, policy: null, ready: false };

async function boot() {
  let session;
  try {
    session = await api.get('/api/auth/session');
  } catch (error) {
    document.body.append(h('p', { class: 'error' }, `Cannot reach the server: ${error.message}`));
    return;
  }

  app.policy = session.policy;
  document.title = session.policy.appName;
  $('#auth-app-name').textContent = session.policy.appName;
  $('#app-name').textContent = session.policy.appName;
  $('#pw-hint').textContent = `At least ${session.policy.passwordMinLength} characters.`;
  show($('#tab-register'), session.policy.allowSelfRegistration);
  show($('#registration-off'), !session.policy.allowSelfRegistration);

  initAuth({ onSession: enter });
  initNav();
  initAccount();

  routeSession(session, { onAuthenticated: enter });
}

/** Called whenever the server confirms a fully authenticated session. */
function enter(session) {
  app.session = session;
  const user = session.user;

  $('#user-name').textContent = user.displayName;
  show($('#user-role'), user.role === 'admin');
  for (const node of $$('.admin-only')) show(node, user.role === 'admin');
  $('#form-profile').displayName.value = user.displayName;
  $('#account-meta').textContent =
    `${user.email} · member since ${formatDate(user.createdAt)} · last sign-in ${user.lastLoginAt ? timeAgo(user.lastLoginAt) : 'now'}`;

  if (!app.ready) {
    initFiles({ user, policy: app.policy });
    initAdmin({ user });
    app.ready = true;
  } else {
    setUser(user);
  }

  showScreen('view-app');
  switchView('files');
  refreshMfaStatus();
}

// ------------------------------------------------------------- navigation --

function initNav() {
  for (const link of $$('.navlink')) {
    link.addEventListener('click', () => switchView(link.dataset.view));
  }
}

function switchView(view) {
  for (const link of $$('.navlink')) link.classList.toggle('is-active', link.dataset.view === view);
  for (const panel of $$('.panel')) show(panel, panel.id === `panel-${view}`);

  if (view === 'files') loadFiles();
  if (view === 'activity') loadActivity();
  if (view === 'admin-users') loadUsers();
  if (view === 'admin-audit') loadAudit();
}

// ---------------------------------------------------------------- account --

function initAccount() {
  submitHandler($('#form-profile'), async (values) => {
    const { user } = await api.patch('/api/users/me', { displayName: values.displayName });
    app.session.user = user;
    $('#user-name').textContent = user.displayName;
    toast('Profile updated', 'success');
  });

  submitHandler($('#form-password'), async (values, form) => {
    await api.post('/api/auth/password', values);
    form.reset();
    toast('Password changed - other devices were signed out', 'success');
  });

  submitHandler($('#form-codes'), async (values, form) => {
    const { backupCodes } = await api.post('/api/auth/mfa/backup-codes', values);
    form.reset();
    showBackupCodes(backupCodes, () => {
      showScreen('view-app');
      refreshMfaStatus();
    });
  });
}

async function refreshMfaStatus() {
  try {
    const me = await api.get('/api/users/me');
    app.session.user = me.user;
    const enrolled = me.user.mfaEnabled;
    $('#mfa-status').textContent = enrolled
      ? `Enrolled on ${formatDate(me.user.mfaEnrolledAt)}. ${me.backupCodesRemaining} unused backup code(s).`
      : 'No authenticator enrolled.';
    for (const node of $$('.mfa-only')) show(node, enrolled);
  } catch {
    /* status is cosmetic */
  }
}

async function loadActivity() {
  const body = clear($('#activity-table').tBodies[0]);
  try {
    const { entries } = await api.get('/api/users/me/activity?limit=100');
    if (entries.length === 0) body.append(h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'Nothing recorded yet.')));
    for (const entry of entries) {
      body.append(h('tr', {},
        h('td', { class: 'muted small', title: entry.ts }, formatDate(entry.ts, { short: true })),
        h('td', {}, entry.action),
        h('td', {}, h('span', { class: `outcome ${entry.outcome}` }, entry.outcome)),
        h('td', {}, entry.object_label ?? entry.object_type ?? '-'),
        h('td', { class: 'muted small' }, entry.ip ?? '-')));
    }
  } catch (error) {
    body.append(h('tr', {}, h('td', { colspan: 5, class: 'error' }, error.message)));
  }
}

// Session lost in another tab, or expired: fall back to the sign-in screen.
window.addEventListener('unhandledrejection', (event) => {
  if (event.reason?.status === 401 && app.ready) {
    toast('Your session ended - please sign in again', 'error');
    setTimeout(() => window.location.reload(), 1200);
  }
});

export { startEnrolment, signOut, setError };
boot();
