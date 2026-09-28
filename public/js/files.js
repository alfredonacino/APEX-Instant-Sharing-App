/* File browsing, uploading and sharing. */
import { api, qs } from './api.js';
import {
  $, $$, clear, confirmAction, fileIcon, formatBytes, formatDate, h, localToIso, setError, show, timeAgo, toast,
} from './ui.js';

const PAGE = 25;

const state = {
  user: null,
  policy: null,
  scope: 'all',
  q: '',
  offset: 0,
  total: 0,
  files: [],
  queue: [],
  recipients: new Map(),   // publicId -> user (upload picker)
  dialogFile: null,
  dialogLink: null,        // the live public link for dialogFile, if any
};

let debounce;

export function initFiles({ user, policy }) {
  state.user = user;
  state.policy = policy;

  $('#upload-limits').textContent =
    `Up to ${policy.maxFilesPerUpload} files, ${formatBytes(policy.maxUploadBytes)} each.`;

  for (const chip of $$('#file-scopes .chip')) {
    chip.addEventListener('click', () => {
      $$('#file-scopes .chip').forEach((c) => c.classList.toggle('is-active', c === chip));
      state.scope = chip.dataset.scope;
      state.offset = 0;
      loadFiles();
    });
  }

  $('#file-search').addEventListener('input', (event) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.q = event.target.value.trim();
      state.offset = 0;
      loadFiles();
    }, 250);
  });

  $('#files-more').addEventListener('click', () => {
    state.offset += PAGE;
    loadFiles({ append: true });
  });

  initUpload();
  initShareDialog();
}

export function setUser(user) {
  state.user = user;
}

// ---------------------------------------------------------------- listing --

export async function loadFiles({ append = false } = {}) {
  const list = $('#file-list');
  if (!append) clear(list).append(h('p', { class: 'muted' }, 'Loading...'));

  try {
    const result = await api.get(`/api/files?${qs({ scope: state.scope, q: state.q, limit: PAGE, offset: state.offset })}`);
    state.total = result.total;
    state.files = append ? [...state.files, ...result.files] : result.files;
    renderFiles();
  } catch (error) {
    clear(list).append(h('p', { class: 'error' }, error.message));
  }
}

function renderFiles() {
  const list = clear($('#file-list'));
  if (state.files.length === 0) {
    list.append(h('div', { class: 'empty' },
      state.q ? 'Nothing matches that search.' :
        state.scope === 'mine' ? 'You have not uploaded anything yet.' :
          state.scope === 'shared' ? 'Nobody has shared a file with you yet.' :
            'No files here yet.'));
  } else {
    for (const file of state.files) list.append(fileCard(file));
  }
  show($('#files-more'), state.files.length < state.total);
}

function tagsFor(file) {
  const tags = [];
  const mine = file.owner?.id === state.user.id;
  if (file.deletedAt) tags.push(h('span', { class: 'tag deleted' }, 'deleted'));
  if (file.visibility === 'everyone') tags.push(h('span', { class: 'tag everyone' }, 'everyone'));
  if (file.hasPublicLink) tags.push(h('span', { class: 'tag public', title: 'Anyone holding the link can download this, without an account' }, 'public link'));
  if (mine && file.shareCount > 0) tags.push(h('span', { class: 'tag shared' }, `${file.shareCount} recipient${file.shareCount === 1 ? '' : 's'}`));
  if (!mine && file.accessVia === 'share') tags.push(h('span', { class: 'tag shared' }, 'shared with you'));
  if (!mine && file.accessVia === 'admin_override') tags.push(h('span', { class: 'tag' }, 'admin view'));
  if (file.expiresAt) tags.push(h('span', { class: 'tag expiring' }, `expires ${timeAgo(file.expiresAt)}`));
  return tags;
}

function fileCard(file) {
  const mine = file.owner?.id === state.user.id;
  const canManage = mine || state.user.role === 'admin';

  const actions = h('div', { class: 'fileactions' });
  if (!file.deletedAt) {
    actions.append(h('a', { class: 'btn tiny primary', href: `/api/files/${encodeURIComponent(file.id)}/download` }, 'Download'));
  }
  if (canManage && !file.deletedAt) {
    actions.append(h('button', { class: 'btn tiny', type: 'button', onclick: () => openShareDialog(file) }, 'Share'));
    actions.append(h('button', {
      class: 'btn tiny danger', type: 'button',
      onclick: () => removeFile(file),
    }, 'Delete'));
  }

  return h('article', { class: `filecard${file.deletedAt ? ' is-deleted' : ''}` },
    h('div', { class: 'fileicon' }, fileIcon(file.mimeType)),
    h('div', {},
      h('div', { class: 'filename' }, file.name),
      file.description ? h('div', { class: 'muted small' }, file.description) : null,
      h('div', { class: 'filemeta' },
        h('span', {}, mine ? 'You' : file.owner?.displayName ?? 'Unknown'),
        h('span', {}, '·'),
        h('span', {}, formatBytes(file.size)),
        h('span', {}, '·'),
        h('span', { title: formatDate(file.createdAt) }, timeAgo(file.createdAt)),
        file.downloadCount ? h('span', {}, `· ${file.downloadCount} download${file.downloadCount === 1 ? '' : 's'}`) : null,
        ...tagsFor(file)),
    ),
    actions);
}

async function removeFile(file) {
  if (!confirmAction(`Delete "${file.name}"? Anyone it was shared with loses access immediately.`)) return;
  try {
    await api.del(`/api/files/${encodeURIComponent(file.id)}`);
    toast(`Deleted ${file.name}`, 'success');
    state.offset = 0;
    loadFiles();
  } catch (error) {
    toast(error.message, 'error');
  }
}

// ---------------------------------------------------------------- uploads --

function initUpload() {
  const dropzone = $('#dropzone');
  const input = $('#file-input');

  dropzone.addEventListener('click', () => input.click());
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      input.click();
    }
  });
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('is-over');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('is-over'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('is-over');
    addToQueue([...e.dataTransfer.files]);
  });
  input.addEventListener('change', () => addToQueue([...input.files]));

  for (const radio of $$('input[name="visibility"]')) {
    radio.addEventListener('change', () => show($('#recipient-box'), radio.value === 'private' && radio.checked));
  }

  let searchTimer;
  $('#recipient-search').addEventListener('input', (event) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => searchPeople(event.target.value, $('#recipient-results'), addRecipient), 220);
  });
  searchPeople('', $('#recipient-results'), addRecipient);

  $('#form-upload').addEventListener('submit', submitUpload);
}

function addToQueue(files) {
  for (const file of files) {
    if (state.queue.length >= state.policy.maxFilesPerUpload) {
      toast(`Only ${state.policy.maxFilesPerUpload} files per upload`, 'error');
      break;
    }
    if (file.size > state.policy.maxUploadBytes) {
      toast(`${file.name} is larger than ${formatBytes(state.policy.maxUploadBytes)}`, 'error');
      continue;
    }
    state.queue.push(file);
  }
  renderQueue();
}

function renderQueue() {
  const list = clear($('#upload-queue'));
  state.queue.forEach((file, index) => {
    list.append(h('li', {},
      h('span', {}, `${fileIcon(file.type)} ${file.name}`),
      h('span', { class: 'row' },
        h('span', { class: 'muted' }, formatBytes(file.size)),
        h('button', {
          class: 'btn tiny', type: 'button', onclick: () => {
            state.queue.splice(index, 1);
            renderQueue();
          },
        }, 'Remove'))));
  });
}

async function searchPeople(query, container, onPick) {
  try {
    const { users } = await api.get(`/api/users/directory?${qs({ q: query })}`);
    const box = clear(container);
    if (users.length === 0) box.append(h('p', { class: 'muted small' }, 'No matching people.'));
    for (const person of users) {
      box.append(h('div', { class: 'person' },
        h('span', {}, `${person.displayName} `, h('span', { class: 'muted' }, person.email)),
        h('button', { class: 'btn tiny', type: 'button', onclick: () => onPick(person) }, 'Add')));
    }
  } catch (error) {
    clear(container).append(h('p', { class: 'error' }, error.message));
  }
}

function addRecipient(person) {
  state.recipients.set(person.id, person);
  renderRecipients();
}

function renderRecipients() {
  const box = clear($('#recipient-chosen'));
  for (const person of state.recipients.values()) {
    box.append(h('button', {
      class: 'chip', type: 'button', title: person.email,
      onclick: () => {
        state.recipients.delete(person.id);
        renderRecipients();
      },
    }, `${person.displayName} ✕`));
  }
}

async function submitUpload(event) {
  event.preventDefault();
  const form = event.currentTarget;
  setError(form, '');

  if (state.queue.length === 0) {
    setError(form, 'Choose at least one file first.');
    return;
  }
  const visibility = form.querySelector('input[name="visibility"]:checked').value;
  if (visibility === 'private' && state.recipients.size === 0) {
    setError(form, 'Pick at least one person, or choose "Everyone with an account".');
    return;
  }

  const data = new FormData();
  for (const file of state.queue) data.append('files', file, file.name);
  data.append('visibility', visibility);
  data.append('description', form.description.value ?? '');
  const expiry = localToIso(form.expiresAt.value);
  if (expiry) data.append('expiresAt', expiry);
  if (visibility === 'private') data.append('shareWith', [...state.recipients.keys()].join(','));

  const progress = $('#upload-progress');
  const button = $('#upload-submit');
  button.disabled = true;
  show(progress, true);
  progress.value = 0;

  try {
    const result = await api.upload('/api/files', data, (percent) => {
      progress.value = percent;
    });
    toast(`Uploaded ${result.files.length} file${result.files.length === 1 ? '' : 's'}`, 'success');
    state.queue = [];
    state.recipients.clear();
    renderQueue();
    renderRecipients();
    form.reset();
    show($('#recipient-box'), true);
    state.scope = 'mine';
    state.offset = 0;
    $$('#file-scopes .chip').forEach((c) => c.classList.toggle('is-active', c.dataset.scope === 'mine'));
    document.querySelector('.navlink[data-view="files"]').click();
    loadFiles();
  } catch (error) {
    setError(form, error.message);
  } finally {
    button.disabled = false;
    show(progress, false);
  }
}

// ----------------------------------------------------------- share dialog --

function initShareDialog() {
  initPublicLink();
  let timer;
  $('#share-search').addEventListener('input', (event) => {
    clearTimeout(timer);
    timer = setTimeout(() => searchPeople(event.target.value, $('#share-results'), grantShare), 220);
  });

  $('#share-everyone').addEventListener('change', async (event) => {
    const visibility = event.target.checked ? 'everyone' : 'private';
    try {
      await api.patch(`/api/files/${encodeURIComponent(state.dialogFile.id)}`, { visibility });
      state.dialogFile.visibility = visibility;
      toast(visibility === 'everyone' ? 'Everyone with an account can now download this' : 'Only the people you picked can download this', 'success');
      loadFiles();
      refreshDialogActivity();
    } catch (error) {
      event.target.checked = !event.target.checked;
      toast(error.message, 'error');
    }
  });

  $('#share-expiry').addEventListener('change', async (event) => {
    try {
      await api.patch(`/api/files/${encodeURIComponent(state.dialogFile.id)}`, { expiresAt: localToIso(event.target.value) });
      toast('Expiry updated', 'success');
      loadFiles();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

export async function openShareDialog(file) {
  state.dialogFile = file;
  const dialog = $('#share-dialog');
  $('#share-title').textContent = `Share "${file.name}"`;
  $('#share-file-meta').textContent = `${formatBytes(file.size)} · uploaded ${formatDate(file.createdAt)}`;
  $('#share-everyone').checked = file.visibility === 'everyone';
  $('#share-expiry').value = file.expiresAt ? new Date(file.expiresAt).toISOString().slice(0, 16) : '';
  clear($('#share-results'));
  $('#share-search').value = '';
  dialog.showModal();
  await Promise.all([refreshShares(), refreshDialogActivity()]);
  searchPeople('', $('#share-results'), grantShare);
}

async function refreshShares() {
  const list = clear($('#share-current'));
  try {
    const detail = await api.get(`/api/files/${encodeURIComponent(state.dialogFile.id)}`);
    renderPublicLink(detail);
    const { shares = [] } = detail;
    if (shares.length === 0) {
      list.append(h('li', { class: 'muted' }, 'Nobody yet.'));
      return;
    }
    for (const share of shares) {
      list.append(h('li', {},
        h('span', {}, `${share.user.displayName} `, h('span', { class: 'muted' }, share.user.email),
          share.expiresAt ? h('span', { class: 'muted small' }, ` · until ${formatDate(share.expiresAt, { short: true })}`) : null),
        h('button', {
          class: 'btn tiny danger', type: 'button',
          onclick: () => revokeShare(share.user.id, share.user.displayName),
        }, 'Revoke')));
    }
  } catch (error) {
    list.append(h('li', { class: 'error' }, error.message));
  }
}

// ----------------------------------------------------------- public links --

/** Paint the public-link controls from a file-detail response. */
function renderPublicLink(detail) {
  const allowed = detail.publicLinksAllowed !== false;
  const link = detail.publicLink ?? null;
  state.dialogLink = link;

  show($('#publiclink-off'), !allowed);
  $('#share-public').disabled = !allowed;
  $('#share-public').checked = Boolean(link);
  show($('#publiclink-detail'), Boolean(link));
  if (!link) return;

  $('#publiclink-url').value = link.url;
  $('#publiclink-expiry').value = link.expiresAt ? new Date(link.expiresAt).toISOString().slice(0, 16) : '';
  $('#publiclink-max').value = link.maxDownloads ?? '';

  const parts = [`created ${formatDate(link.createdAt, { short: true })}`];
  parts.push(`${link.downloadCount} download${link.downloadCount === 1 ? '' : 's'}`);
  if (link.lastDownloadAt) parts.push(`last ${timeAgo(link.lastDownloadAt)}`);
  if (link.maxDownloads) parts.push(`limit ${link.maxDownloads}`);
  $('#publiclink-stats').textContent = parts.join(' · ');
}

function initPublicLink() {
  const fileId = () => encodeURIComponent(state.dialogFile.id);

  $('#share-public').addEventListener('change', async (event) => {
    const wantLink = event.target.checked;
    try {
      if (wantLink) {
        await api.post(`/api/files/${fileId()}/link`, {
          expiresAt: localToIso($('#publiclink-expiry').value),
          maxDownloads: Number($('#publiclink-max').value) || null,
        });
        toast('Public link created - anyone holding it can download this file', 'success');
      } else {
        await api.del(`/api/files/${fileId()}/link`);
        toast('Public link turned off', 'success');
      }
      await refreshShares();
      await refreshDialogActivity();
      loadFiles();
    } catch (error) {
      event.target.checked = !wantLink;
      toast(error.message, 'error');
    }
  });

  $('#publiclink-copy').addEventListener('click', async () => {
    const field = $('#publiclink-url');
    try {
      // Only available in a secure context; fall back to a selection the
      // recipient can copy by hand over plain HTTP.
      await navigator.clipboard.writeText(field.value);
      toast('Link copied', 'success');
    } catch {
      field.select();
      toast('Press Ctrl+C to copy the selected link', 'info');
    }
  });

  $('#publiclink-rotate').addEventListener('click', async () => {
    if (!confirmAction('Replace this link with a new one? The current URL stops working immediately.')) return;
    try {
      await api.post(`/api/files/${fileId()}/link`, {
        expiresAt: localToIso($('#publiclink-expiry').value),
        maxDownloads: Number($('#publiclink-max').value) || null,
      });
      toast('New link created - the old one no longer works', 'success');
      await refreshShares();
      await refreshDialogActivity();
    } catch (error) {
      toast(error.message, 'error');
    }
  });

  // Changing a limit keeps the same URL, so links already handed out survive.
  const updateLimits = async () => {
    if (!state.dialogLink) return;
    try {
      await api.patch(`/api/files/${fileId()}/link`, {
        expiresAt: localToIso($('#publiclink-expiry').value),
        maxDownloads: Number($('#publiclink-max').value) || null,
      });
      toast('Link updated', 'success');
      await refreshShares();
    } catch (error) {
      toast(error.message, 'error');
    }
  };
  $('#publiclink-expiry').addEventListener('change', updateLimits);
  $('#publiclink-max').addEventListener('change', updateLimits);
}

async function grantShare(person) {
  try {
    await api.post(`/api/files/${encodeURIComponent(state.dialogFile.id)}/shares`, {
      userIds: [person.id],
      expiresAt: localToIso($('#share-expiry').value),
    });
    toast(`Shared with ${person.displayName}`, 'success');
    await Promise.all([refreshShares(), refreshDialogActivity()]);
    loadFiles();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function revokeShare(userId, name) {
  try {
    await api.del(`/api/files/${encodeURIComponent(state.dialogFile.id)}/shares/${encodeURIComponent(userId)}`);
    toast(`Access removed for ${name}`, 'success');
    await Promise.all([refreshShares(), refreshDialogActivity()]);
    loadFiles();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function refreshDialogActivity() {
  const body = clear($('#share-activity').tBodies[0]);
  try {
    const { entries } = await api.get(`/api/files/${encodeURIComponent(state.dialogFile.id)}/activity?limit=20`);
    if (entries.length === 0) {
      body.append(h('tr', {}, h('td', { class: 'muted' }, 'No activity recorded yet.')));
      return;
    }
    for (const entry of entries) {
      body.append(h('tr', {},
        h('td', { class: 'muted small' }, formatDate(entry.ts, { short: true })),
        h('td', {}, entry.actor_email ?? 'system'),
        h('td', {}, h('span', { class: `outcome ${entry.outcome}` }, entry.action))));
    }
  } catch (error) {
    body.append(h('tr', {}, h('td', { class: 'error' }, error.message)));
  }
}
