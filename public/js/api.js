/* Thin fetch wrapper: JSON in, JSON out, CSRF header attached automatically. */

export class ApiError extends Error {
  constructor(status, payload) {
    super(payload?.error || `Request failed (${status})`);
    this.status = status;
    this.code = payload?.code ?? null;
    this.details = payload?.details ?? null;
  }
}

function csrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)apex\.csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

async function request(method, path, body, { raw = false } = {}) {
  const headers = { Accept: 'application/json' };
  if (!['GET', 'HEAD'].includes(method)) headers['X-CSRF-Token'] = csrfToken();
  if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';

  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });

  if (raw) return response;
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) throw new ApiError(response.status, payload);
  return payload;
}

export const api = {
  get: (path) => request('GET', path),
  post: (path, body) => request('POST', path, body ?? {}),
  patch: (path, body) => request('PATCH', path, body ?? {}),
  del: (path) => request('DELETE', path),

  /** Multipart upload with progress; XHR because fetch cannot report it. */
  upload(path, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', path);
      xhr.responseType = 'text';
      xhr.withCredentials = true;
      xhr.setRequestHeader('X-CSRF-Token', csrfToken());
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable && onProgress) onProgress(Math.round((event.loaded / event.total) * 100));
      });
      xhr.addEventListener('load', () => {
        let payload = {};
        try {
          payload = xhr.responseText ? JSON.parse(xhr.responseText) : {};
        } catch {
          payload = { error: 'Unexpected response from the server' };
        }
        if (xhr.status >= 200 && xhr.status < 300) resolve(payload);
        else reject(new ApiError(xhr.status, payload));
      });
      xhr.addEventListener('error', () => reject(new ApiError(0, { error: 'Network error during upload' })));
      xhr.addEventListener('abort', () => reject(new ApiError(0, { error: 'Upload cancelled' })));
      xhr.send(formData);
    });
  },
};

export const qs = (params) =>
  Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
