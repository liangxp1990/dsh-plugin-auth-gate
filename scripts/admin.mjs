#!/usr/bin/env node
/**
 * Offline account administration for dsh-plugin-auth-gate.
 *
 *   node scripts/admin.mjs <dataDir> <command> [...]
 *
 * Commands:
 *   create-admin <name> [--password <pw>]   create the first administrator
 *   set-password <name> [--password <pw>]   reset an account password
 *   disable-mfa <name>                      administrator override: switch MFA off
 *   delete <name>                           remove an account
 *   list                                    list accounts
 *   logout-all                              invalidate every session
 *
 * The data directory is the workspace's .dsh-auth folder (see the auth.dataDir
 * config). Run it on the machine that serves the workspace.
 */
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { AuthStore } from '../lib/store.js';

const [dataDir, command, ...rest] = process.argv.slice(2);
if (dataDir === undefined || command === undefined) {
  console.error(new URL(import.meta.url).pathname.split('/').pop() + ': <dataDir> <command> [...]');
  process.exit(2);
}

const store = new AuthStore(resolve(dataDir));
await store.init();

function option(name) {
  const at = rest.indexOf(name);
  return at === -1 ? undefined : rest[at + 1];
}

async function askPassword() {
  const given = option('--password');
  if (given !== undefined) return given;
  const readline = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await readline.question('password: ');
  readline.close();
  return answer;
}

switch (command) {
  case 'create-admin': {
    const password = await askPassword();
    await store.createUser(rest[0], password, { admin: true });
    console.log('created administrator ' + rest[0]);
    break;
  }
  case 'set-password': {
    await store.setPassword(rest[0], await askPassword());
    await store.destroyUserSessions(rest[0]);
    console.log('password updated; all sessions for ' + rest[0] + ' were signed out');
    break;
  }
  case 'disable-mfa': {
    await store.mfaDisable(rest[0]);
    console.log('MFA disabled for ' + rest[0]);
    break;
  }
  case 'delete': {
    await store.deleteUser(rest[0]);
    console.log('deleted ' + rest[0]);
    break;
  }
  case 'list': {
    for (const user of store.listUsers()) {
      const mfa = user.mfa ? 'mfa:on(codes:' + user.backupCodesRemaining + ')' : 'mfa:off';
      console.log([user.name, user.admin ? 'admin' : 'user', mfa, user.createdAt].join('  '));
    }
    if (store.listUsers().length === 0) console.log('(no accounts)');
    break;
  }
  case 'logout-all': {
    for (const user of store.listUsers()) await store.destroyUserSessions(user.name);
    console.log('all sessions invalidated');
    break;
  }
  default:
    console.error('unknown command ' + command);
    process.exit(2);
}
