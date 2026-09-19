/**
 * Signed session cookies. The cookie value is `sid.signature` where the
 * signature is HMAC-SHA256(workspace secret, sid); the session row itself
 * lives in the workspace {@link AuthStore}, so logout, logout-all, expiry,
 * and workspace rebinding all take effect without waiting for cookie expiry.
 * @module dsh-plugin-auth-gate/session
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

const SIGNATURE_LENGTH = 32;

function sign(secret, sid) {
  return createHmac('sha256', secret).update(sid).digest();
}

/** Build the Set-Cookie value for a fresh session. */
export function sessionCookie(name, sid, secret, ttlMs, { secure = false } = {}) {
  const mac = sign(secret, sid).toString('base64url');
  const attributes = [
    name + '=' + sid + '.' + mac,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + Math.floor(ttlMs / 1000)
  ];
  if (secure) attributes.push('Secure');
  return attributes.join('; ');
}

/** Clear the session cookie regardless of validity. */
export function clearSessionCookie(name, { secure = false } = {}) {
  const attributes = [name + '=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (secure) attributes.push('Secure');
  return attributes.join('; ');
}

/** Parse the cookie header into a map. */
export function parseCookies(header) {
  const cookies = {};
  if (typeof header !== 'string') return cookies;
  for (const part of header.split(';')) {
    const at = part.indexOf('=');
    if (at === -1) continue;
    cookies[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return cookies;
}

/**
 * Extract and validate a session from the request.
 * @returns the session row, or null when absent/invalid/expired/wrong workspace.
 */
export function readSession(req, store, cookieName, workspace, now = Date.now()) {
  const raw = parseCookies(req.headers.cookie)[cookieName];
  if (raw === undefined) return null;
  const dot = raw.lastIndexOf('.');
  if (dot === -1) return null;
  const sid = raw.slice(0, dot);
  let mac;
  try {
    mac = Buffer.from(raw.slice(dot + 1), 'base64url');
  } catch {
    return null;
  }
  if (mac.length !== SIGNATURE_LENGTH) return null;
  const expected = sign(store.secret, sid);
  if (!timingSafeEqual(mac, expected)) return null;
  const session = store.getSession(sid, now);
  if (session === null) return null;
  // workspace isolation: a session minted for workspace A never authenticates workspace B
  if (session.wks !== workspace) return null;
  return { ...session, sid };
}
