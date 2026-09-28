/*
 * The page an anonymous recipient lands on at /p/<token>.
 *
 * Deliberately self-contained: it never asks for a session, never touches the
 * authenticated API, and shows only what the link endpoint chooses to reveal.
 */
import { api } from './api.js';
import { $, formatBytes, formatDate, show } from './ui.js';

/** Messages for the states the server distinguishes, in the recipient's terms. */
const TITLES = {
  link_revoked: 'This link has been turned off',
  link_expired: 'This link has expired',
  file_expired: 'This file has expired',
  file_deleted: 'This file has been deleted',
  download_limit_reached: 'This link has been used up',
  forbidden: 'Public links are switched off',
  not_found: 'This link is not valid',
};

function fileIcon(mime = '') {
  if (mime.startsWith('image/')) return 'IMG';
  if (mime.startsWith('video/')) return 'VID';
  if (mime.startsWith('audio/')) return 'AUD';
  if (mime.includes('pdf')) return 'PDF';
  if (mime.includes('zip') || mime.includes('tar') || mime.includes('compressed')) return 'ZIP';
  if (mime.startsWith('text/')) return 'TXT';
  return 'FILE';
}

function problem(code, message) {
  show($('#public-loading'), false);
  show($('#public-ready'), false);
  show($('#public-problem'), true);
  $('#public-problem-title').textContent = TITLES[code] ?? 'This link is not available';
  $('#public-problem-text').textContent = message;
}

export async function renderPublicPage(token) {
  show($('#view-public'), true);
  document.title = 'Shared file';

  let data;
  try {
    data = await api.get(`/api/public/${encodeURIComponent(token)}`);
  } catch (error) {
    problem(error.code ?? 'not_found', error.message);
    return;
  }

  const { file, sharedBy, appName, expiresAt, downloadsRemaining } = data;
  document.title = `${file.name} · ${appName}`;
  $('#public-app-name').textContent = appName;
  $('#public-shared-by').textContent = sharedBy ? `Shared with you by ${sharedBy}` : 'Shared with you';

  $('#public-icon').textContent = fileIcon(file.mimeType);
  $('#public-name').textContent = file.name;
  $('#public-description').textContent = file.description || '';
  show($('#public-description'), Boolean(file.description));

  const meta = [formatBytes(file.size), file.mimeType];
  if (expiresAt) meta.push(`link expires ${formatDate(expiresAt, { short: true })}`);
  if (downloadsRemaining !== null) {
    meta.push(`${downloadsRemaining} download${downloadsRemaining === 1 ? '' : 's'} left`);
  }
  $('#public-meta').textContent = meta.join(' · ');

  const link = $('#public-download');
  link.href = `/api/public/${encodeURIComponent(token)}/download`;
  // A capability URL should not leak to whatever the recipient visits next.
  link.rel = 'noreferrer';
  if (downloadsRemaining === 0) {
    link.setAttribute('aria-disabled', 'true');
    link.classList.add('is-disabled');
  }

  // The checksum lets a careful recipient verify what they received.
  $('#public-note').textContent = `SHA-256 ${file.sha256}`;

  show($('#public-loading'), false);
  show($('#public-ready'), true);
}
