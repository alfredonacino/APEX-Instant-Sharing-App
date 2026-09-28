/**
 * Policy an administrator can change at runtime.
 *
 * Each setting has a definition: its type, and the environment-derived value
 * used until an administrator decides otherwise. Reads fall back to that
 * default, so a fresh deployment behaves exactly as its .env says; the first
 * write stores a row, and from then on the stored value wins - including across
 * restarts, which is the whole point of not keeping this in the environment.
 */
import { db, nowIso } from '../lib/db.js';
import { config } from '../config.js';
import { badRequest } from '../lib/validate.js';

export const SETTING_DEFINITIONS = {
  allowSelfRegistration: {
    type: 'boolean',
    default: () => config.allowSelfRegistration,
    label: 'Visitors may create their own account',
    help: 'When off, only an administrator can create accounts. Existing accounts are unaffected.',
  },
  allowPublicLinks: {
    type: 'boolean',
    default: () => config.allowPublicLinks,
    label: 'Files may be shared by public link',
    help: 'When off, no new public links can be created and every existing link stops working immediately.',
  },
};

const readStmt = db.prepare('SELECT value FROM app_settings WHERE key = ?');
const writeStmt = db.prepare(
  `INSERT INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
   ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,
                                  updated_by = excluded.updated_by`,
);

function definition(key) {
  const def = SETTING_DEFINITIONS[key];
  if (!def) throw badRequest(`Unknown setting: ${key}`);
  return def;
}

function decode(def, raw) {
  if (def.type === 'boolean') return raw === '1';
  return raw;
}

function encode(def, value, key) {
  if (def.type === 'boolean') {
    if (typeof value !== 'boolean') throw badRequest(`${key} must be true or false`);
    return value ? '1' : '0';
  }
  return String(value);
}

/** Current value: the stored decision if there is one, otherwise the .env default. */
export function getSetting(key) {
  const def = definition(key);
  const row = readStmt.get(key);
  return row ? decode(def, row.value) : def.default();
}

export function allSettings() {
  return Object.fromEntries(Object.keys(SETTING_DEFINITIONS).map((key) => [key, getSetting(key)]));
}

/**
 * Store a decision. Returns the previous value too, so the caller can record a
 * meaningful before/after in the audit trail and skip a no-op write.
 */
export function setSetting(key, value, actorId = null) {
  const def = definition(key);
  const from = getSetting(key);
  writeStmt.run(key, encode(def, value, key), nowIso(), actorId);
  return { key, from, to: getSetting(key), changed: from !== value };
}

/** Where each value currently comes from - shown in the admin screen. */
export function settingsDetail() {
  return Object.entries(SETTING_DEFINITIONS).map(([key, def]) => {
    const row = db.prepare('SELECT value, updated_at, updated_by FROM app_settings WHERE key = ?').get(key);
    return {
      key,
      value: getSetting(key),
      type: def.type,
      label: def.label,
      help: def.help,
      source: row ? 'admin' : 'environment',
      envDefault: def.default(),
      updatedAt: row?.updated_at ?? null,
    };
  });
}
