/* Sign-in, registration, TOTP enrolment and the second-factor challenge. */
import { api, ApiError } from './api.js';
import { $, $$, clear, h, setError, show, toast } from './ui.js';

const VIEWS = ['view-auth', 'view-mfa', 'view-enrol', 'view-codes', 'view-app'];

export function showScreen(id) {
  for (const view of VIEWS) show(document.getElementById(view), view === id);
}

/** Route to the screen that matches the session stage the server reports. */
export function routeSession(session, { onAuthenticated }) {
  if (!session.authenticated) {
    if (session.stage === 'mfa_required') showScreen('view-mfa');
    else if (session.stage === 'mfa_setup') startEnrolment().catch((e) => toast(e.message, 'error'));
    else showScreen('view-auth');
    return;
  }
  onAuthenticated(session);
}

export function initAuth({ onSession }) {
  // Always re-route on the stage the server reports: a password alone may leave
  // the session at "enrol MFA" or "enter your code" rather than signed in.
  const handle = (session, extra = {}) => {
    const proceed = () => routeSession(session, { onAuthenticated: onSession });
    if (extra.backupCodes?.length) return showBackupCodes(extra.backupCodes, proceed);
    return proceed();
  };

  // Sign in / create account tabs
  for (const tab of $$('[data-authtab]')) {
    tab.addEventListener('click', () => {
      $$('[data-authtab]').forEach((t) => t.classList.toggle('is-active', t === tab));
      show($('#form-login'), tab.dataset.authtab === 'login');
      show($('#form-register'), tab.dataset.authtab === 'register');
    });
  }

  submitHandler($('#form-login'), async (values) => {
    const session = await api.post('/api/auth/login', { email: values.email, password: values.password });
    $('#form-login').reset();
    handle(session);
  });

  submitHandler($('#form-register'), async (values) => {
    const session = await api.post('/api/auth/register', values);
    $('#form-register').reset();
    if (session.firstAccount) toast('This is the first account, so it has administrator rights.', 'success', 8000);
    handle(session);
  });

  submitHandler($('#form-mfa'), async (values) => {
    const session = await api.post('/api/auth/mfa/verify', { token: values.token });
    $('#form-mfa').reset();
    handle(session);
  });

  submitHandler($('#form-backup'), async (values) => {
    const result = await api.post('/api/auth/mfa/verify', { backupCode: values.backupCode });
    $('#form-backup').reset();
    toast(`Backup code accepted. ${result.backupCodesRemaining} code(s) left - generate a new set from Account.`, 'info', 9000);
    handle(result);
  });

  submitHandler($('#form-enrol'), async (values) => {
    const result = await api.post('/api/auth/mfa/enable', { token: values.token });
    $('#form-enrol').reset();
    handle(result, { backupCodes: result.backupCodes });
  });

  for (const button of $$('[data-action="signout"]')) {
    button.addEventListener('click', () => signOut());
  }
}

export async function signOut() {
  try {
    await api.post('/api/auth/logout');
  } finally {
    window.location.reload();
  }
}

/** Fetch a fresh secret + QR and show the enrolment screen. */
export async function startEnrolment(password) {
  const setup = await api.post('/api/auth/mfa/setup', password ? { password } : {});
  $('#enrol-qr').src = setup.qrDataUrl;
  $('#enrol-secret').textContent = setup.secret;
  setError($('#form-enrol'), '');
  showScreen('view-enrol');
}

export function showBackupCodes(codes, done) {
  const list = clear($('#codes-list'));
  for (const code of codes) list.append(h('li', {}, code));

  const text = `${document.title} backup codes\nGenerated ${new Date().toLocaleString()}\n\n${codes.join('\n')}\n`;
  $('#codes-copy').onclick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast('Codes copied to the clipboard', 'success');
    } catch {
      toast('Could not access the clipboard - select and copy them manually', 'error');
    }
  };
  $('#codes-download').onclick = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const link = h('a', { href: url, download: 'apex-backup-codes.txt' });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };
  $('#codes-done').onclick = () => done();
  showScreen('view-codes');
}

/** Wire a form: collect values, clear errors, disable while in flight. */
export function submitHandler(form, handler) {
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setError(form, '');
    const button = form.querySelector('button[type="submit"], button:not([type])');
    if (button) button.disabled = true;
    try {
      await handler(Object.fromEntries(new FormData(form).entries()), form);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'mfa_setup_required') {
        await startEnrolment().catch(() => {});
      } else {
        setError(form, error.message);
      }
    } finally {
      if (button) button.disabled = false;
    }
  });
}
