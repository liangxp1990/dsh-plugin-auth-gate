/**
 * Durable account, MFA, session, and login-rate state for one workspace.
 * Everything lives in a per-workspace data directory (default
 * `<workspace>/.dsh-auth`), so two DSH workspaces never share accounts,
 * sessions, or lockouts — the workspace session-isolation boundary.
 * @module dsh-plugin-auth-gate/store
 */
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const scrypt = promisify(scryptCb);
const SCRYPT = { N: 16384, r: 8, p: 1, keyLength: 32 };

function hashPassword(password) {
  const salt = randomBytes(16);
  return scrypt(String(password), salt, SCRYPT.keyLength, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p }).then((key) =>
    ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$')
  );
}

async function verifyPassword(password, stored) {
  try {
    const [scheme, n, r, p, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const key = await scrypt(String(password), Buffer.from(saltB64, 'base64'), expected.length, {
      N: Number(n), r: Number(r), p: Number(p)
    });
    return key.length === expected.length && timingSafeEqual(key, expected);
  } catch {
    return false;
  }
}

const sha256 = (text) => createHash('sha256').update(String(text)).digest('hex');

/** One JSON file read/write pair with an atomic rename on save. */
class JsonFile {
  constructor(path, initial) {
    this.path = path;
    this.data = structuredClone(initial);
  }
  async load() {
    try {
      this.data = JSON.parse(await readFile(this.path, 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  async save() {
    const temporary = this.path + '.tmp';
    await writeFile(temporary, JSON.stringify(this.data, null, 2));
    await rename(temporary, this.path);
  }
}

/**
 * The auth store. All mutating methods persist synchronously before resolving,
 * because a lost account write is a lockout and a lost lockout write defeats
 * rate limiting across restarts.
 */
export class AuthStore {
  /** @param directory absolute data-directory path for one workspace */
  constructor(directory) {
    this.directory = directory;
    this.users = new JsonFile(join(directory, 'users.json'), {});
    this.state = new JsonFile(join(directory, 'state.json'), { failures: {}, sessions: {} });
    this.secret = '';
  }

  async init() {
    await mkdir(this.directory, { recursive: true });
    await this.users.load();
    await this.state.load();
    const secretPath = join(this.directory, 'secret.key');
    try {
      this.secret = (await readFile(secretPath, 'utf8')).trim();
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      this.secret = randomBytes(32).toString('base64url');
      await writeFile(secretPath, this.secret + '\n', { mode: 0o600 });
    }
    this.sweep();
  }

  /** @param ttlMs session lifetime; expired rows are pruned lazily */
  sweep(now = Date.now()) {
    const sessions = this.state.data.sessions;
    let changed = false;
    for (const [sid, session] of Object.entries(sessions)) {
      if (session.exp <= now) {
        delete sessions[sid];
        changed = true;
      }
    }
    if (changed) return this.state.save();
  }

  //#region accounts
  hasAnyUser() {
    return Object.keys(this.users.data).length > 0;
  }

  listUsers() {
    return Object.entries(this.users.data).map(([name, user]) => ({
      name,
      admin: user.admin === true,
      initial: user.initial === true,
      mfa: user.mfa?.confirmed === true,
      backupCodesRemaining: user.mfa?.codes?.length ?? 0,
      createdAt: user.createdAt
    }));
  }

  getUser(name) {
    return this.users.data[String(name)];
  }

  async createUser(name, password, { admin = false } = {}) {
    name = String(name).trim();
    if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) throw new Error('username must be 1–64 characters of [a-zA-Z0-9_.-]');
    if (String(password).length < 8) throw new Error('password must be at least 8 characters');
    if (this.users.data[name] !== undefined) throw new Error('user already exists');
    // The very first account ever created is the initial administrator: the
    // only role allowed to manage users, no matter who runs the command.
    const initial = !this.hasAnyUser();
    this.users.data[name] = {
      hash: await hashPassword(password),
      admin: admin || initial,
      initial,
      createdAt: new Date().toISOString(),
      mfa: null
    };
    await this.users.save();
  }

  /** The bootstrap-created administrator — the only user-management principal. */
  isInitialAdmin(name) {
    return this.users.data[String(name)]?.initial === true;
  }

  initialAdminName() {
    for (const [name, user] of Object.entries(this.users.data)) {
      if (user.initial === true) return name;
    }
    return null;
  }

  /** Verify credentials; also the gate for MFA-secret changes. */
  async verifyCredentials(name, password) {
    const user = this.users.data[String(name)];
    if (user === undefined) {
      // burn comparable time so absent users are indistinguishable
      await scrypt(String(password), Buffer.alloc(16), 32, SCRYPT);
      return false;
    }
    return verifyPassword(password, user.hash);
  }

  async setPassword(name, password) {
    const user = this.users.data[String(name)];
    if (user === undefined) throw new Error('no such user');
    if (String(password).length < 8) throw new Error('password must be at least 8 characters');
    user.hash = await hashPassword(password);
    await this.users.save();
  }

  async deleteUser(name) {
    if (this.users.data[name] === undefined) throw new Error('no such user');
    if (this.users.data[name].initial === true) throw new Error('the initial administrator cannot be deleted');
    delete this.users.data[name];
    const sessions = this.state.data.sessions;
    for (const [sid, session] of Object.entries(sessions)) {
      if (session.user === name) delete sessions[sid];
    }
    await this.users.save();
    await this.state.save();
  }
  //#endregion

  //#region MFA
  /** Generate (or regenerate) a pending TOTP secret; inactive until confirmed. */
  async mfaBegin(name) {
    const user = this.users.data[String(name)];
    if (user === undefined) throw new Error('no such user');
    const { generateSecret } = await import('./totp.js');
    user.mfa = { pending: generateSecret(), confirmed: false, codes: [] };
    await this.users.save();
    return user.mfa.pending;
  }

  /** Confirm the pending secret with a live code; returns the 10 backup codes, plaintext, once. */
  async mfaConfirm(name, code) {
    const user = this.users.data[String(name)];
    if (user?.mfa?.pending === undefined) throw new Error('no pending MFA setup');
    const { verifyTotp } = await import('./totp.js');
    if (!verifyTotp(user.mfa.pending, code)) return null;
    user.mfa.secret = user.mfa.pending;
    delete user.mfa.pending;
    user.mfa.confirmed = true;
    user.mfa.confirmedAt = new Date().toISOString();
    user.mfa.codes = Array.from({ length: 10 }, () => randomBytes(5).toString('hex')); // 10 hex chars each
    const plaintext = [...user.mfa.codes];
    user.mfa.codes = user.mfa.codes.map(sha256);
    await this.users.save();
    return plaintext;
  }

  /** A TOTP code or an unused backup code; backup codes burn on use. */
  async verifySecondFactor(name, code) {
    const user = this.users.data[String(name)];
    if (user?.mfa?.confirmed !== true) return false;
    const { verifyTotp } = await import('./totp.js');
    if (user.mfa.secret !== undefined && verifyTotp(user.mfa.secret, code)) return true;
    const digest = sha256(String(code).trim().toLowerCase());
    const at = user.mfa.codes.indexOf(digest);
    if (at !== -1) {
      user.mfa.codes.splice(at, 1);
      await this.users.save();
      return true;
    }
    return false;
  }

  mfaEnabled(name) {
    return this.users.data[String(name)]?.mfa?.confirmed === true;
  }

  mfaRemainingCodes(name) {
    return this.users.data[String(name)]?.mfa?.codes?.length ?? 0;
  }

  /** Administrator override: switch MFA off for an account and drop its codes. */
  async mfaDisable(name) {
    const user = this.users.data[String(name)];
    if (user === undefined) throw new Error('no such user');
    user.mfa = null;
    await this.users.save();
  }
  //#endregion

  //#region login rate limiting
  failureKey(ip, name) {
    return sha256(ip + '|' + String(name).toLowerCase()).slice(0, 24);
  }

  /** Sliding-window failure count with escalating lockout; persisted. */
  checkRate(key, now = Date.now()) {
    const record = this.state.data.failures[key];
    if (record === undefined) return { allowed: true };
    if (record.lockedUntil > now) return { allowed: false, retryAfterMs: record.lockedUntil - now };
    if (now - record.firstAt > 15 * 60_000) return { allowed: true }; // window lapsed
    return { allowed: true };
  }

  async recordFailure(key, now = Date.now()) {
    const failures = this.state.data.failures;
    let record = failures[key];
    if (record === undefined || now - record.firstAt > 15 * 60_000) {
      record = failures[key] = { firstAt: now, count: 0, lockedUntil: 0 };
    }
    record.count += 1;
    if (record.count >= 5) {
      const strikes = Math.floor(record.count / 5) - 1;
      record.lockedUntil = now + Math.min(15 * 60_000 * 2 ** strikes, 24 * 3600_000);
    }
    await this.state.save();
  }

  async clearFailures(key) {
    if (this.state.data.failures[key] !== undefined) {
      delete this.state.data.failures[key];
      await this.state.save();
    }
  }
  //#endregion

  //#region sessions
  /** Create a server-side session row; the cookie carries only sid + signature. */
  async createSession(name, workspace, ttlMs, now = Date.now()) {
    const sid = randomBytes(24).toString('base64url');
    this.state.data.sessions[sid] = { user: name, wks: workspace, iat: now, exp: now + ttlMs };
    await this.state.save();
    return sid;
  }

  getSession(sid, now = Date.now()) {
    const session = this.state.data.sessions[String(sid)];
    if (session === undefined || session.exp <= now) return null;
    return session;
  }

  /** Is this session still valid for the workspace it is trying to reach? */
  sessionMatchesWorkspace(sid, workspace) {
    const session = this.state.data.sessions[String(sid)];
    return session !== undefined && session.wks === workspace;
  }

  async destroySession(sid) {
    if (this.state.data.sessions[sid] !== undefined) {
      delete this.state.data.sessions[sid];
      await this.state.save();
    }
  }

  async destroyUserSessions(name) {
    const sessions = this.state.data.sessions;
    let changed = false;
    for (const [sid, session] of Object.entries(sessions)) {
      if (session.user === name) {
        delete sessions[sid];
        changed = true;
      }
    }
    if (changed) await this.state.save();
  }
  //#endregion
}
