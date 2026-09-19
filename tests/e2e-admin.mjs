/**
 * User-management authorization tests: the module belongs to the initial
 * administrator only. Runs a fresh gated server and a real HTTP session.
 */
import { Context } from '@deepseek-ai/cordis';
import { GatedWebServer } from '../lib/webserver.js';

const ctx = new Context();
await ctx.plugin(GatedWebServer, {
  host: '127.0.0.1', port: 0,
  compression: 'gzip', compressionLevel: 1, compressionThresholdBytes: 256,
  auth: { dataDir: '/tmp/e2e-admin-data', sessionTtlHours: 1 }
});
await new Promise(r => setTimeout(r, 1200));
function findServer(context) {
  const direct = context.get?.('webServer');
  if (direct) return direct;
  for (const child of context.children ?? []) {
    const found = findServer(child);
    if (found) return found;
  }
  return null;
}
const port = findServer(ctx).port;
const base = 'http://127.0.0.1:' + port;

let pass = 0, fail = 0;
const check = (name, cond) => { cond ? pass++ : fail++; console.log(cond ? 'PASS' : 'FAIL', name); };
async function call(path, { method = 'GET', body, cookie } = {}) {
  const res = await fetch(base + path, {
    method, redirect: 'manual',
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, text, json, headers: res.headers };
}
const cookieOf = (res) => res.headers.get('set-cookie').split(';')[0];

// a SPA-like fallback so '/' exists
ctx.webServer.registerFallback((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body>spa</body></html>'); });

// ── first entry: bootstrap the initial administrator ──
let r = await call('/'); 
check('first visit redirects to /login', r.status === 302 && r.headers.get('location').startsWith('/login?next='));
r = await call('/login');
check('login page shows bootstrap mode', r.text.includes('"bootstrap"'));
r = await call('/auth/bootstrap', { method: 'POST', body: { username: 'root', password: 'root-password-1' } });
check('bootstrap creates initial admin', r.status === 200 && r.json.ok);
const rootCookie = cookieOf(r);
r = await call('/auth/session', { cookie: rootCookie });
check('session reports initial admin', r.json.user === 'root' && r.json.admin === true);

// ── admin page: initial admin can open ──
r = await call('/admin/users', { cookie: rootCookie });
check('initial admin opens user management', r.status === 200 && r.text.includes('"manage"'));
r = await call('/admin/users');
check('anonymous is redirected to login', r.status === 302 && r.headers.get('location').includes('admin%2Fusers'));

// ── initial admin creates an ordinary user and a second admin ──
r = await call('/auth/users', { method: 'POST', body: { username: 'alice', password: 'alice-password' }, cookie: rootCookie });
check('create ordinary user', r.status === 200);
r = await call('/auth/users', { method: 'POST', body: { username: 'bob', password: 'bob-password', admin: true }, cookie: rootCookie });
check('create second admin', r.status === 200);
r = await call('/auth/users', { cookie: rootCookie });
check('list marks initial admin', r.json.initialAdmin === 'root' && r.json.users.find(u => u.name === 'root').initial === true);

// ── login as bob (admin but NOT initial) ──
r = await call('/auth/login', { method: 'POST', body: { username: 'bob', password: 'bob-password' } });
const bobCookie = cookieOf(r);
check('bob signs in', r.status === 200);

// ── bob (non-initial admin) is denied user management everywhere ──
r = await call('/admin/users', { cookie: bobCookie });
check('bob gets 403 page', r.status === 403 && r.text.includes('"forbidden"'));
r = await call('/auth/users', { cookie: bobCookie });
check('bob cannot list users', r.status === 403 && r.json.error.includes('initial administrator'));
r = await call('/auth/users', { method: 'POST', body: { username: 'eve', password: 'eve-password' }, cookie: bobCookie });
check('bob cannot create users', r.status === 403);
r = await call('/auth/users/delete', { method: 'POST', body: { username: 'alice' }, cookie: bobCookie });
check('bob cannot delete users', r.status === 403);
r = await call('/auth/mfa/disable', { method: 'POST', body: { username: 'root' }, cookie: bobCookie });
check('bob cannot disable root MFA', r.status === 403);
r = await call('/auth/logout-all', { method: 'POST', body: { scope: 'all' }, cookie: bobCookie });
check('bob cannot sign out everyone', r.status === 403);

// ── ordinary user also denied ──
r = await call('/auth/login', { method: 'POST', body: { username: 'alice', password: 'alice-password' } });
const aliceCookie = cookieOf(r);
r = await call('/auth/users', { cookie: aliceCookie });
check('alice cannot list users', r.status === 403);

// ── initial admin operations work ──
r = await call('/auth/users/delete', { method: 'POST', body: { username: 'bob' }, cookie: rootCookie });
check('initial admin deletes bob', r.status === 200);
r = await call('/auth/users/delete', { method: 'POST', body: { username: 'root' }, cookie: rootCookie });
check('initial admin cannot delete himself', r.status === 400);
r = await call('/auth/logout-all', { method: 'POST', body: { scope: 'all' }, cookie: rootCookie });
check('initial admin signs out everyone', r.status === 200);
r = await call('/auth/session', { cookie: bobCookie.length ? rootCookie : rootCookie });
check('root session revoked by logout-all', r.status === 401);

console.log('RESULT: ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
