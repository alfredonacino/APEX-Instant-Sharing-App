import { config } from '../config.js';

/**
 * The origin to put in front of a path when the app has to hand out an absolute
 * URL, such as a public share link.
 *
 * PUBLIC_BASE_URL wins when set - that is the deployment telling us its real
 * public name. Otherwise it is derived from the request, which is correct behind
 * a proxy that preserves the Host header and sets X-Forwarded-Proto (and needs
 * `trust proxy` configured, or req.protocol reports the proxy hop instead).
 */
export function baseUrlFor(req) {
  if (config.publicBaseUrl) return config.publicBaseUrl;
  const host = req.get('host');
  if (!host) return config.publicHost ? `https://${config.publicHost}` : '';
  return `${req.protocol}://${host}`;
}
