#!/usr/bin/env node
/**
 * Remove the stored bytes of files deleted more than N days ago.
 * The database row and the whole audit trail are kept; only the blob goes.
 *
 *   node scripts/purge-deleted.js --days 30 [--dry-run]
 */
import { parseArgs } from 'node:util';
import { db, closeDb, nowIso } from '../src/lib/db.js';
import { audit } from '../src/lib/audit.js';
import { purgeBlob } from '../src/services/files.service.js';

const { values } = parseArgs({
  options: { days: { type: 'string', default: '30' }, 'dry-run': { type: 'boolean', default: false } },
});

const cutoff = new Date(Date.now() - Number(values.days) * 86_400_000).toISOString();
const rows = db
  .prepare(`SELECT id, public_id, original_name, stored_name, size_bytes FROM files
             WHERE deleted_at IS NOT NULL AND deleted_at < ? AND stored_name != ''`)
  .all(cutoff);

console.log(`${rows.length} file(s) deleted before ${cutoff}`);

for (const row of rows) {
  if (values['dry-run']) {
    console.log(`  would purge ${row.original_name} (${row.size_bytes} bytes)`);
    continue;
  }
  await purgeBlob(row.stored_name);
  db.prepare('UPDATE files SET stored_name = ?, updated_at = ? WHERE id = ?').run('', nowIso(), row.id);
  audit({
    action: 'file.delete', outcome: 'success', objectType: 'file', objectId: row.public_id,
    objectLabel: row.original_name, details: { operation: 'purge_blob', bytes: row.size_bytes, via: 'cli' },
  });
  console.log(`  purged ${row.original_name}`);
}

closeDb();
