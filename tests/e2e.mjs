
import { Context } from '@deepseek-ai/cordis';
import { GatedWebServer } from '/root/dsh登录及工作区用户隔离/dsh-plugin-auth-gate/lib/webserver.js';
import { gzipSync } from 'node:zlib';

const ctx = new Context();
ctx.emit && 0;
await ctx.plugin(GatedWebServer, {
  host: '127.0.0.1',
  port: 0,
  compression: 'gzip',
  compressionLevel: 1,
  compressionThresholdBytes: 256,
  auth: { dataDir: '/tmp/e2e-auth-data', sessionTtlHours: 1 }
});
await new Promise(r => setTimeout(r, 1500));
await new Promise(r => setTimeout(r, 500));
function findServer(context) {
  const direct = context.get?.('webServer');
  if (direct) return direct;
  for (const child of context.children ?? []) {
    const found = findServer(child);
    if (found) return found;
  }
  return null;
}
const server = findServer(ctx);
const port = server.port;
console.log('listening on', port);

// a protected route and a fallback (SPA)
ctx.webServer.register({ kind: 'prefix', path: '/api', handler: (req, res) => { res.writeHead(200); res.end('api-ok'); } });
ctx.webServer.registerFallback((req, res) => { res.writeHead(200, {'Content-Type':'text/html'}); res.end('<html><body>spa</body></html>'); });

async function fetchRaw(path, opts = {}) {
  const res = await fetch('http://127.0.0.1:' + port + path, { redirect: 'manual', ...opts });
  return res;
}

let pass = 0, fail = 0;
const check = (name, cond) => { cond ? pass++ : fail++; console.log(cond ? 'PASS' : 'FAIL', name); };

// 1. unauthenticated SPA → redirect to /login
let r = await fetchRaw('/');
check('unauth / redirects', r.status === 302 && r.headers.get('location').startsWith('/login?next=%2F'));

// 2. unauth API → 401 JSON
r = await fetchRaw('/api/foo');
check('unauth /api 401', r.status === 401);

// 3. login page (no users) served
r = await fetchRaw('/login');
check('login page 200', r.status === 200);
check('login page gzip', r.headers.get('content-encoding') === 'gzip');
const html = await r.text();
check('login page bootstrap mode', html.includes('"bootstrap"'));

// 4. bootstrap from non-loopback blocked (simulate by header? remote addr is loopback here, so bootstrap allowed)
r = await fetchRaw('/auth/bootstrap', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username: 'admin', password: 'password123' }) });
const boot = await r.json();
check('bootstrap ok', r.status === 200 && boot.ok);
const cookie = r.headers.get('set-cookie').split(';')[0];
check('session cookie issued', cookie.startsWith('dsh_auth='));

// 5. second bootstrap rejected
r = await fetchRaw('/auth/bootstrap', { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
check('bootstrap once only', r.status === 409);

// 6. authed request passes
r = await fetchRaw('/api/foo', { headers: { cookie } });
check('authed /api 200', r.status === 200 && (await r.text()) === 'api-ok');
r = await fetchRaw('/', { headers: { cookie } });
check('authed / served fallback', r.status === 200 && (await r.text()).includes('spa'));

// 7. login wrong password 401
r = await fetchRaw('/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username:'admin', password:'wrong' }) });
check('bad login 401', r.status === 401);

// 8. POST without JSON content-type 415
r = await fetchRaw('/auth/login', { method: 'POST', body: 'a=1' });
check('form post 415', r.status === 415);

// 9. /auth/health public
r = await fetchRaw('/auth/health');
check('health public', r.status === 200);

// 10. MFA setup + login with TOTP
r = await fetchRaw('/auth/mfa/setup', { method: 'POST', headers: {'Content-Type':'application/json', cookie }, body:'{}' });
const setup = await r.json();
check('mfa setup', r.status === 200 && setup.secret.length === 32);
r = await fetchRaw('/auth/mfa/qr.svg', { headers: { cookie } });
check('qr svg', r.status === 200 && (await r.text()).startsWith('<svg'));
const totp = await import('/root/dsh登录及工作区用户隔离/dsh-plugin-auth-gate/lib/totp.js');
const code = totp.totpNow?.(setup.secret) ?? null;
// compute TOTP inline
const { createHmac } = await import('node:crypto');
const b32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const clean = setup.secret;
let bits=0,val=0; const bytes=[];
for (const ch of clean){ val=(val<<5)|b32.indexOf(ch); bits+=5; if(bits>=8){ bytes.push((val>>>(bits-8))&255); bits-=8; } }
const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
const dig = createHmac('sha1', Buffer.from(bytes)).update(buf).digest();
const off = dig[dig.length-1]&15;
const otp = String((((dig[off]&127)<<24)|(dig[off+1]<<16)|(dig[off+2]<<8)|dig[off+3])%1e6).padStart(6,'0');
r = await fetchRaw('/auth/mfa/confirm', { method: 'POST', headers: {'Content-Type':'application/json', cookie }, body: JSON.stringify({ code: otp }) });
const confirm = await r.json();
check('mfa confirm 10 codes', confirm.backupCodes?.length === 10);

// 11. login now requires OTP
r = await fetchRaw('/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username:'admin', password:'password123' }) });
const mfaReq = await r.json();
check('mfaRequired prompt', mfaReq.mfaRequired === true);
r = await fetchRaw('/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username:'admin', password:'password123', otp: confirm.backupCodes[0] }) });
check('backup code login', r.status === 200);
r = await fetchRaw('/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username:'admin', password:'password123', otp: confirm.backupCodes[0] }) });
check('backup code single use', r.status === 401);
const otp2 = (() => { const b=Buffer.alloc(8); b.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000))); const d=createHmac('sha1',Buffer.from(bytes)).update(b).digest(); const o=d[d.length-1]&15; return String((((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3])%1e6).padStart(6,'0'); })();
r = await fetchRaw('/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username:'admin', password:'password123', otp: otp2 }) });
check('totp login', r.status === 200);

// 12. admin disables MFA
const cookie2 = r.headers.get('set-cookie').split(';')[0];
r = await fetchRaw('/auth/mfa/disable', { method: 'POST', headers: {'Content-Type':'application/json', cookie: cookie2 }, body: JSON.stringify({ username:'admin', password:'password123' }) });
check('mfa disable', r.status === 200);
r = await fetchRaw('/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username:'admin', password:'password123' }) });
check('login without otp after disable', r.status === 200);

// 13. WebSocket upgrade gating
ctx.webServer.registerUpgrade({ path: '/ws', handler: (req, socket) => {
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.end();
}});
const http = await import('node:http');
const crypto = await import('node:crypto');
const key = crypto.randomBytes(16).toString('base64');
const wsReq = http.request({ host:'127.0.0.1', port, path:'/ws', headers: { Connection:'Upgrade', Upgrade:'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': 13 } });
wsReq.end();
const wsResult = await new Promise(resolve => {
  wsReq.on('upgrade', () => resolve('upgraded'));
  wsReq.on('response', res => resolve('http-' + res.statusCode));
  wsReq.on('error', e => resolve('error-' + e.message));
});
console.log('ws unauth result:', wsResult);
check('unauth ws upgrade rejected', wsResult === 'http-401' || wsResult.startsWith('error-') || wsResult.startsWith('http-4'));

// 14. registered upgrade route passes when authed
const wsReq2 = http.request({ host:'127.0.0.1', port, path:'/ws', headers: { Connection:'Upgrade', Upgrade:'websocket', 'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64'), 'Sec-WebSocket-Version': 13, cookie: cookie2 } });
wsReq2.end();
const wsResult2 = await new Promise(resolve => {
  wsReq2.on('upgrade', () => resolve('upgraded'));
  wsReq2.on('response', res => resolve('http-' + res.statusCode));
  wsReq2.on('error', e => resolve('error-' + e.message));
});
check('authed ws upgrade passes', wsResult2 === 'upgraded');

console.log('RESULT: ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
