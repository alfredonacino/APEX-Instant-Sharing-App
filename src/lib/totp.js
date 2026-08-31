import QRCode from 'qrcode';
import { generateSecret, generateURI, verify } from 'otplib';
import { config } from '../config.js';

/** One 30-second step of tolerance either side, for clock drift. */
const EPOCH_TOLERANCE_SECONDS = 30;

export function newSecret() {
  return generateSecret();
}

export function otpauthUri(secret, accountLabel) {
  return generateURI({ issuer: config.appName, label: accountLabel, secret });
}

export function qrDataUrl(uri) {
  return QRCode.toDataURL(uri, { errorCorrectionLevel: 'M', margin: 1, width: 240 });
}

/**
 * Verify a 6-digit code.
 * Returns { valid, step } - the step lets the caller reject a replayed code.
 */
export async function checkToken(secret, token) {
  try {
    const result = await verify({ secret, token, epochTolerance: EPOCH_TOLERANCE_SECONDS });
    return { valid: Boolean(result?.valid), step: result?.timeStep ?? null };
  } catch {
    return { valid: false, step: null };
  }
}
