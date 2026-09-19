/**
 * Small HTTP helpers shared by the gate and its auth routes: cookie-backed
 * redirects, bounded JSON bodies, gzip-compressed responses for remote
 * clients, and cache headers for login-page statics.
 * @module dsh-plugin-auth-gate/http-util
 */
import { gzipSync } from 'node:zlib';

/** Does the client accept gzip? (remote browsers do; loopback tools often do not bother) */
export function acceptsGzip(req) {
  return /gzip|\*/.test(String(req.headers['accept-encoding'] ?? ''));
}

/** Send a body with content-type; gzip when the client accepts it and the body earns it. */
export function sendBody(req, res, status, body, contentType, { gzip = true, cacheControl = 'no-store' } = {}) {
  const buffer = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const headers = { 'Content-Type': contentType, 'Cache-Control': cacheControl };
  if (gzip && acceptsGzip(req) && buffer.length >= 1024) {
    const compressed = gzipSync(buffer);
    if (compressed.length < buffer.length) {
      headers['Content-Encoding'] = 'gzip';
      headers['Vary'] = 'Accept-Encoding';
      res.writeHead(status, { ...headers, 'Content-Length': compressed.length });
      return res.end(compressed);
    }
  }
  headers['Content-Length'] = buffer.length;
  res.writeHead(status, headers);
  return res.end(buffer);
}

export function sendJson(req, res, status, value) {
  sendBody(req, res, status, JSON.stringify(value) + '\n', 'application/json; charset=utf-8');
}

export function sendHtml(req, res, status, html) {
  sendBody(req, res, status, html, 'text/html; charset=utf-8');
}

export function redirect(res, location) {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
  res.end();
}

/** Read a request body, capped; returns {} for an empty body, throws beyond the cap. */
export function readJsonBody(req, capBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > capBytes) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim();
      if (text === '') return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

export function isLoopback(req) {
  const remote = req.socket.remoteAddress ?? '';
  return remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
}
