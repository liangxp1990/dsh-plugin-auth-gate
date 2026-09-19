/**
 * The login gate: one object that owns the auth store, the signed-session
 * cookie, and the wrappers that put every HTTP route and WebSocket upgrade
 * behind a valid session. The gate exposes its own routes (/login and the
 * /auth/* control plane) and classifies everything else: API paths answer 401
 * JSON, browser navigations redirect to /login?next=…
 * @module dsh-plugin-auth-gate/gate
 */
import { createHash } from 'node:crypto';
import { isAbsolute, join, resolve } from 'node:path';
import { AuthStore } from './store.js';
import * as session from './session.js';
import { provisioningUri } from './totp.js';
import { encodeSvg } from './qrcode.js';
import { renderLoginPage } from './login-page.js';
import { renderAdminPage } from './admin-page.js';
import { sendJson, sendHtml, redirect, readJsonBody, isLoopback } from './http-util.js';

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

/**
 * @param config the `auth` block of the gated server config
 * @param workspaceRoot absolute workspace directory the server serves
 */
export class AuthGate {
  constructor(config = {}, workspaceRoot = process.cwd()) {
    this.config = {
      dataDir: config.dataDir || '',
      cookieName: config.cookieName || 'dsh_auth',
      sessionTtlHours: config.sessionTtlHours ?? 24 * 7,
      publicPaths: config.publicPaths ?? [],
      trustProxy: config.trustProxy === true,
      issuer: config.issuer || 'DSH'
    };
    const root = isAbsolute(this.config.dataDir) ? this.config.dataDir : join(resolve(workspaceRoot), this.config.dataDir || '.dsh-auth');
    this.workspaceRoot = resolve(workspaceRoot);
    // Workspace isolation identity: sessions and accounts are keyed to it.
    this.workspaceId = createHash('sha256').update(this.workspaceRoot).digest('hex').slice(0, 16);
    this.store = new AuthStore(root);
  }

  async init() {
    await this.store.init();
  }

  /** Session lifetime in ms. */
  get ttl() {
    return this.config.sessionTtlHours * 3600_000;
  }

  clientAddress(req) {
    if (this.config.trustProxy) {
      const forwarded = req.headers['x-forwarded-for'];
      if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress ?? 'unknown';
  }

  /** True when the gate itself answers the path — never wrapped, never gated. */
  isExempt(pathname) {
    return pathname === '/login' || pathname.startsWith('/auth/') || this.config.publicPaths.includes(pathname);
  }

  //#region the control-plane routes
  routes() {
    const gate = this;
    return [
      { kind: 'exact', path: '/login', handler: (req, res) => gate.handleLoginRequest(req, res) },
      { kind: 'exact', path: '/admin/users', handler: (req, res) => gate.handleAdminPage(req, res) },
      { kind: 'prefix', path: '/auth', handler: (req, res) => gate.handleAuthRequest(req, res) }
    ];
  }

  async handleLoginRequest(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' });
      return res.end();
    }
    const url = new URL(req.url, 'http://gate');
    const bootstrap = !this.store.hasAnyUser();
    if (bootstrap && !isLoopback(req)) {
      return sendHtml(req, res, 403, renderLoginPage({ locale: this.detectLocale(req), theme: this.detectTheme(req), mode: 'bootstrap-remote' }));
    }
    const existing = this.readValidSession(req);
    if (existing !== null && !bootstrap) return redirect(res, safeNext(url.searchParams.get('next')));
    return sendHtml(req, res, 200, renderLoginPage({
      locale: this.detectLocale(req),
      theme: this.detectTheme(req),
      mode: bootstrap ? 'bootstrap' : 'login',
      next: safeNext(url.searchParams.get('next'))
    }));
  }

  /**
   * The user-management page. Only the initial administrator (the account
   * created by first-entry bootstrap) may open it; every other session gets
   * 403, including other admins.
   */
  handleAdminPage(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' });
      return res.end();
    }
    const sessionRow = this.readValidSession(req);
    if (sessionRow === null) {
      return redirect(res, '/login?next=' + encodeURIComponent('/admin/users'));
    }
    if (!this.store.isInitialAdmin(sessionRow.user)) {
      return sendHtml(req, res, 403, renderAdminPage({
        locale: this.detectLocale(req),
        theme: this.detectTheme(req),
        mode: 'forbidden',
        initialAdmin: this.store.initialAdminName()
      }));
    }
    return sendHtml(req, res, 200, renderAdminPage({
      locale: this.detectLocale(req),
      theme: this.detectTheme(req),
      mode: 'manage',
      user: sessionRow.user,
      initialAdmin: sessionRow.user
    }));
  }

  async handleAuthRequest(req, res) {
    const path = new URL(req.url, 'http://gate').pathname;
    const method = req.method ?? 'GET';
    try {
      if (method !== 'GET' && !isJsonRequest(req)) return sendJson(req, res, 415, { error: 'content-type must be application/json' });
      const body = method === 'POST' ? await readJsonBody(req) : {};

      if (path === '/auth/health' && method === 'GET') {
        return sendJson(req, res, 200, { ok: true, workspace: this.workspaceId, bootstrap: !this.store.hasAnyUser() });
      }

      // ── bootstrap: only when the store is empty AND the request is local ──
      if (path === '/auth/bootstrap' && method === 'POST') {
        if (this.store.hasAnyUser()) return sendJson(req, res, 409, { error: 'administrator already exists' });
        if (!isLoopback(req)) return sendJson(req, res, 403, { error: 'the first administrator can only be created from the machine' });
        const { username, password } = body;
        await this.store.createUser(String(username ?? ''), String(password ?? ''), { admin: true });
        return this.establishSession(req, res, String(username).trim());
      }

      if (path === '/auth/login' && method === 'POST') {
        const { username, password, otp } = body;
        const name = String(username ?? '').trim();
        const key = this.store.failureKey(this.clientAddress(req), name);
        const rate = this.store.checkRate(key);
        if (!rate.allowed) {
          res.setHeader('Retry-After', Math.ceil(rate.retryAfterMs / 1000));
          return sendJson(req, res, 429, { error: 'too many failed attempts', retryAfterMs: rate.retryAfterMs });
        }
        const ok = await this.store.verifyCredentials(name, String(password ?? ''));
        if (!ok) {
          await this.store.recordFailure(key);
          return sendJson(req, res, 401, { error: 'invalid username or password' });
        }
        if (this.store.mfaEnabled(name)) {
          if (otp === undefined || otp === '') return sendJson(req, res, 200, { mfaRequired: true });
          const secondOk = await this.store.verifySecondFactor(name, String(otp));
          if (!secondOk) {
            await this.store.recordFailure(key);
            return sendJson(req, res, 401, { error: 'invalid verification code', mfaRequired: true });
          }
        }
        await this.store.clearFailures(key);
        return this.establishSession(req, res, name);
      }

      // ── everything below requires a session ──
      const sessionRow = this.readValidSession(req);
      if (sessionRow === null) return sendJson(req, res, 401, { error: 'unauthenticated', loginUrl: '/login' });
      const user = this.store.getUser(sessionRow.user);

      if (path === '/auth/session' && method === 'GET') {
        return sendJson(req, res, 200, {
          user: sessionRow.user,
          admin: user?.admin === true,
          workspace: this.workspaceId,
          workspaceRoot: this.workspaceRoot,
          mfa: this.store.mfaEnabled(sessionRow.user),
          backupCodesRemaining: this.store.mfaRemainingCodes(sessionRow.user),
          expiresAt: sessionRow.exp
        });
      }

      if (path === '/auth/logout' && method === 'POST') {
        await this.store.destroySession(sessionRow.sid);
        res.setHeader('Set-Cookie', session.clearSessionCookie(this.config.cookieName));
        return sendJson(req, res, 200, { ok: true });
      }

      if (path === '/auth/password' && method === 'POST') {
        const { current, next } = body;
        if (!(await this.store.verifyCredentials(sessionRow.user, String(current ?? '')))) {
          return sendJson(req, res, 403, { error: 'current password incorrect' });
        }
        await this.store.setPassword(sessionRow.user, String(next ?? ''));
        await this.store.destroyUserSessions(sessionRow.user);
        res.setHeader('Set-Cookie', session.clearSessionCookie(this.config.cookieName));
        return sendJson(req, res, 200, { ok: true, relogin: true });
      }

      if (path === '/auth/mfa/setup' && method === 'POST') {
        const secret = await this.store.mfaBegin(sessionRow.user);
        const uri = provisioningUri(secret, sessionRow.user, this.config.issuer);
        return sendJson(req, res, 200, { secret, uri, qrUrl: '/auth/mfa/qr.svg' });
      }

      if (path === '/auth/mfa/qr.svg' && method === 'GET') {
        const user = this.store.getUser(sessionRow.user);
        const secret = user?.mfa?.pending;
        if (secret === undefined) return sendJson(req, res, 404, { error: 'no pending MFA setup' });
        const svg = encodeSvg(provisioningUri(secret, sessionRow.user, this.config.issuer));
        res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(svg);
      }

      if (path === '/auth/mfa/confirm' && method === 'POST') {
        const codes = await this.store.mfaConfirm(sessionRow.user, String(body.code ?? ''));
        if (codes === null) return sendJson(req, res, 401, { error: 'code did not match; scan the QR and retry' });
        return sendJson(req, res, 200, { ok: true, backupCodes: codes });
      }

      if (path === '/auth/mfa/codes' && method === 'POST') {
        const ok = await this.store.verifySecondFactor(sessionRow.user, String(body.code ?? ''));
        if (!ok) return sendJson(req, res, 403, { error: 'verification code required' });
        const user = this.store.getUser(sessionRow.user);
        const { randomBytes } = await import('node:crypto');
        const plaintext = Array.from({ length: 10 }, () => randomBytes(5).toString('hex'));
        user.mfa.codes = plaintext.map((code) => createHash('sha256').update(code).digest('hex'));
        await this.store.users.save();
        return sendJson(req, res, 200, { ok: true, backupCodes: plaintext });
      }

      if (path === '/auth/mfa/disable' && method === 'POST') {
        const target = String(body.username ?? sessionRow.user);
        if (target !== sessionRow.user && !this.store.isInitialAdmin(sessionRow.user)) {
          return sendJson(req, res, 403, { error: 'initial administrator required' });
        }
        if (target === sessionRow.user) {
          // self-service still proves possession of the password + current second factor
          if (!(await this.store.verifyCredentials(sessionRow.user, String(body.password ?? '')))) {
            return sendJson(req, res, 403, { error: 'password required' });
          }
        }
        await this.store.mfaDisable(target);
        return sendJson(req, res, 200, { ok: true, username: target });
      }

      // User management belongs to the initial administrator alone; other
      // admins created through the panel are ordinary accounts with no
      // user-management reach.
      if (path === '/auth/users' && method === 'GET') {
        if (!this.store.isInitialAdmin(sessionRow.user)) return sendJson(req, res, 403, { error: 'initial administrator required' });
        return sendJson(req, res, 200, { users: this.store.listUsers(), initialAdmin: this.store.initialAdminName() });
      }

      if (path === '/auth/users' && method === 'POST') {
        if (!this.store.isInitialAdmin(sessionRow.user)) return sendJson(req, res, 403, { error: 'initial administrator required' });
        await this.store.createUser(String(body.username ?? ''), String(body.password ?? ''), { admin: body.admin === true });
        return sendJson(req, res, 200, { ok: true });
      }

      if (path === '/auth/users/delete' && method === 'POST') {
        if (!this.store.isInitialAdmin(sessionRow.user)) return sendJson(req, res, 403, { error: 'initial administrator required' });
        const target = String(body.username ?? '');
        if (target === sessionRow.user) return sendJson(req, res, 400, { error: 'cannot delete yourself' });
        await this.store.deleteUser(target);
        return sendJson(req, res, 200, { ok: true });
      }

      if (path === '/auth/logout-all' && method === 'POST') {
        if (!this.store.isInitialAdmin(sessionRow.user) && body.scope !== 'self') {
          return sendJson(req, res, 403, { error: 'initial administrator required' });
        }
        const target = this.store.isInitialAdmin(sessionRow.user) && body.scope === 'all' ? null : sessionRow.user;
        if (target === null) {
          const all = this.store.listUsers();
          for (const entry of all) await this.store.destroyUserSessions(entry.name);
        } else {
          await this.store.destroyUserSessions(target);
        }
        res.setHeader('Set-Cookie', session.clearSessionCookie(this.config.cookieName));
        return sendJson(req, res, 200, { ok: true });
      }

      return sendJson(req, res, 404, { error: 'unknown auth endpoint' });
    } catch (error) {
      return sendJson(req, res, 400, { error: error instanceof Error ? error.message : 'bad request' });
    }
  }

  /** Mint the session row and set the signed cookie. */
  async establishSession(req, res, name) {
    const sid = await this.store.createSession(name, this.workspaceId, this.ttl);
    const secure = this.isSecure(req);
    res.setHeader('Set-Cookie', session.sessionCookie(this.config.cookieName, sid, this.store.secret, this.ttl, { secure }));
    return sendJson(req, res, 200, { ok: true, user: name, workspace: this.workspaceId });
  }

  isSecure(req) {
    return req.socket.encrypted === true || req.headers['x-forwarded-proto'] === 'https';
  }

  detectLocale(req) {
    const cookie = session.parseCookies(req.headers.cookie)['dsh_locale'];
    if (cookie === 'zh' || cookie === 'en') return cookie;
    const language = String(req.headers['accept-language'] ?? '');
    return language.toLowerCase().startsWith('zh') ? 'zh' : 'en';
  }

  detectTheme(req) {
    const cookie = session.parseCookies(req.headers.cookie)['dsh_theme'];
    return cookie === 'light' || cookie === 'dark' ? cookie : 'auto';
  }

  readValidSession(req) {
    return session.readSession(req, this.store, this.config.cookieName, this.workspaceId);
  }
  //#endregion

  //#route guard section
  /** Wrap one HTTP handler so it only runs for a valid session. */
  guardHttp(handler) {
    const gate = this;
    return async function guarded(req, res) {
      const pathname = requestPath(req);
      if (gate.isExempt(pathname)) return handler(req, res);
      const sessionRow = gate.readValidSession(req);
      if (sessionRow !== null) {
        req.auth = { user: sessionRow.user, sid: sessionRow.sid, workspace: sessionRow.wks };
        return handler(req, res);
      }
      await gate.store.sweep();
      if (pathname.startsWith('/api') || wantsJson(req)) {
        return sendJson(req, res, 401, { error: 'unauthenticated', loginUrl: '/login' });
      }
      const url = new URL(req.url ?? '/', 'http://gate');
      return redirect(res, '/login?next=' + encodeURIComponent(pathname + url.search));
    };
  }

  /** Wrap one upgrade handler; an unauthenticated socket gets a bare 401. */
  guardUpgrade(handler) {
    const gate = this;
    return function guardedUpgrade(req, socket, head) {
      const pathname = requestPath(req);
      if (gate.isExempt(pathname)) return handler(req, socket, head);
      const sessionRow = gate.readValidSession(req);
      if (sessionRow !== null) {
        req.auth = { user: sessionRow.user, sid: sessionRow.sid, workspace: sessionRow.wks };
        return handler(req, socket, head);
      }
      socket.end('HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"error":"unauthenticated","loginUrl":"/login"}\n');
    };
  }
  //#endregion
}

function requestPath(req) {
  try {
    return new URL(req.url ?? '/', 'http://gate').pathname;
  } catch {
    return '/';
  }
}

function isJsonRequest(req) {
  return String(req.headers['content-type'] ?? '').toLowerCase().includes('application/json');
}

function wantsJson(req) {
  const accept = String(req.headers.accept ?? '');
  return accept.includes('application/json') && !accept.includes('text/html');
}

function safeNext(next) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//')) return '/';
  return next;
}
