/* Small DOM helpers. Everything user-supplied goes in as text, never as HTML. */

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/** h('div', {class: 'x', onclick: fn}, 'text', childNode) */
export function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
    else if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key === 'html') throw new Error('h() does not accept raw HTML');
    else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function show(node, visible = true) {
  node.hidden = !visible;
}

export function toast(message, kind = 'info', ms = 4500) {
  const node = h('div', { class: `toast ${kind}`, role: 'status' }, message);
  $('#toasts').append(node);
  setTimeout(() => {
    node.style.opacity = '0';
    node.style.transition = 'opacity .25s';
    setTimeout(() => node.remove(), 250);
  }, ms);
}

export function setError(form, message) {
  const slot = form?.querySelector('[data-error]');
  if (!slot) {
    if (message) toast(message, 'error');
    return;
  }
  slot.textContent = message ?? '';
  slot.hidden = !message;
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function formatDate(iso, { short = false } = {}) {
  if (!iso) return '-';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString(undefined, short
    ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { dateStyle: 'medium', timeStyle: 'short' });
}

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
const STEPS = [['year', 31536e6], ['month', 2592e6], ['day', 864e5], ['hour', 36e5], ['minute', 6e4]];

export function timeAgo(iso) {
  if (!iso) return '-';
  const delta = new Date(iso).getTime() - Date.now();
  for (const [unit, ms] of STEPS) {
    if (Math.abs(delta) >= ms) return RELATIVE.format(Math.round(delta / ms), unit);
  }
  return 'just now';
}

/** datetime-local value (local time) -> ISO string, or null. */
export function localToIso(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

const ICONS = [
  [/^image\//, '🖼️'], [/^video\//, '🎬'], [/^audio\//, '🎵'],
  [/pdf/, '📕'], [/zip|compress|tar|rar|7z/, '🗜️'],
  [/sheet|excel|csv/, '📊'], [/word|document|rtf/, '📝'],
  [/presentation|powerpoint/, '📽️'], [/^text\//, '📄'],
];

export function fileIcon(mime = '') {
  for (const [re, icon] of ICONS) if (re.test(mime)) return icon;
  return '📦';
}

export function confirmAction(message) {
  return window.confirm(message);
}
