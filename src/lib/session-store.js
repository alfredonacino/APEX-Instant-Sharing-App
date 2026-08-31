import session from 'express-session';
import { db } from './db.js';
import { config } from '../config.js';

/**
 * express-session store backed by the same SQLite database as the rest of the
 * app, so sessions survive restarts and an administrator can revoke them.
 */
export class SqliteSessionStore extends session.Store {
  #get = db.prepare('SELECT data, expires_at FROM sessions WHERE sid = ?');
  #upsert = db.prepare(`
    INSERT INTO sessions (sid, user_id, data, expires_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(sid) DO UPDATE SET user_id = excluded.user_id, data = excluded.data, expires_at = excluded.expires_at
  `);
  #destroy = db.prepare('DELETE FROM sessions WHERE sid = ?');
  #destroyUser = db.prepare('DELETE FROM sessions WHERE user_id = ?');
  #touch = db.prepare('UPDATE sessions SET expires_at = ? WHERE sid = ?');
  #count = db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?');
  #prune = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
  #clear = db.prepare('DELETE FROM sessions');

  constructor({ ttlMs = 3_600_000, pruneIntervalMs = 300_000 } = {}) {
    super();
    this.ttlMs = ttlMs;
    this.pruneTimer = setInterval(() => this.prune(), pruneIntervalMs);
    this.pruneTimer.unref?.();
  }

  #expiry(sess) {
    const cookieExpiry = sess?.cookie?.expires ? new Date(sess.cookie.expires).getTime() : null;
    return cookieExpiry || Date.now() + this.ttlMs;
  }

  get(sid, callback) {
    try {
      const row = this.#get.get(sid);
      if (!row) return callback(null, null);
      if (row.expires_at <= Date.now()) {
        this.#destroy.run(sid);
        return callback(null, null);
      }
      return callback(null, JSON.parse(row.data));
    } catch (error) {
      return callback(error);
    }
  }

  set(sid, sess, callback = () => {}) {
    try {
      this.#upsert.run(sid, sess?.userId ?? null, JSON.stringify(sess), this.#expiry(sess));
      return callback(null);
    } catch (error) {
      return callback(error);
    }
  }

  touch(sid, sess, callback = () => {}) {
    try {
      this.#touch.run(this.#expiry(sess), sid);
      return callback(null);
    } catch (error) {
      return callback(error);
    }
  }

  destroy(sid, callback = () => {}) {
    try {
      this.#destroy.run(sid);
      return callback(null);
    } catch (error) {
      return callback(error);
    }
  }

  length(callback) {
    try {
      return callback(null, this.#count.get(Date.now()).n);
    } catch (error) {
      return callback(error);
    }
  }

  clear(callback = () => {}) {
    try {
      this.#clear.run();
      return callback(null);
    } catch (error) {
      return callback(error);
    }
  }

  /** Sign a user out of every device - used on password change, disable and MFA reset. */
  destroyByUser(userId) {
    return this.#destroyUser.run(userId).changes;
  }

  prune() {
    try {
      this.#prune.run(Date.now());
    } catch (error) {
      console.error('[sessions] prune failed', error);
    }
  }
}

/** Single store instance shared by the session middleware and the routes that revoke sessions. */
export const sessionStore = new SqliteSessionStore({ ttlMs: config.sessionIdleMs });
