#!/usr/bin/env node
/**
 * Create (or promote) an administrator from the command line.
 *
 *   node scripts/create-admin.js --email a@b.com --name "Ada" --password "..."
 *   node scripts/create-admin.js --email a@b.com --promote
 *
 * The account still has to enrol its own authenticator at first sign-in.
 */
import { parseArgs } from 'node:util';
import { audit } from '../src/lib/audit.js';
import * as users from '../src/services/users.service.js';
import { closeDb } from '../src/lib/db.js';
import { config } from '../src/config.js';

const { values } = parseArgs({
  options: {
    email: { type: 'string' },
    name: { type: 'string' },
    password: { type: 'string' },
    promote: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
});

if (values.help || !values.email) {
  console.log(`Usage:
  node scripts/create-admin.js --email <email> --name <name> --password <password>
  node scripts/create-admin.js --email <email> --promote      # promote an existing account`);
  process.exit(values.help ? 0 : 1);
}

const existing = users.findByEmail(values.email);

if (values.promote) {
  if (!existing) {
    console.error(`No account found for ${values.email}`);
    process.exit(1);
  }
  users.setRoleAndStatus(existing.id, { role: 'admin', status: 'active' });
  audit({
    action: 'admin.user.update', outcome: 'success', objectType: 'user', objectId: existing.public_id,
    targetUserId: existing.id, details: { operation: 'promote', via: 'cli' },
  });
  console.log(`${values.email} is now an administrator.`);
} else {
  if (existing) {
    console.error(`${values.email} already exists - use --promote to grant admin rights.`);
    process.exit(1);
  }
  if (!values.name || !values.password) {
    console.error('--name and --password are required when creating an account');
    process.exit(1);
  }
  if (values.password.length < config.passwordMinLength) {
    console.error(`Password must be at least ${config.passwordMinLength} characters`);
    process.exit(1);
  }
  const created = await users.createUser({
    email: values.email.toLowerCase(),
    displayName: values.name,
    password: values.password,
    role: 'admin',
  });
  audit({
    action: 'auth.register', outcome: 'success', objectType: 'user', objectId: created.public_id,
    targetUserId: created.id, details: { role: 'admin', via: 'cli' },
  });
  console.log(`Administrator ${values.email} created. Enrol an authenticator at first sign-in.`);
}

closeDb();
