/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30 s step) with RFC 4648 Base32 —
 * zero dependencies, compatible with Google Authenticator, 1Password, Authy,
 * and every other standard authenticator.
 * @module dsh-plugin-auth-gate/totp
 */
import { createHmac, randomBytes } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encode bytes as unpadded RFC 4648 Base32. */
export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** Decode unpadded or padded RFC 4648 Base32; throws on a foreign character. */
export function base32Decode(text) {
  const clean = text.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('invalid base32 character');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(bytes);
}

/** Generate a fresh 160-bit TOTP secret, Base32 encoded (the authenticator form). */
export function generateSecret() {
  return base32Encode(randomBytes(20));
}

function hotp(secretBytes, counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secretBytes).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, '0');
}

/**
 * Verify a 6-digit code against the secret at the current time.
 * Accepts the previous and next step (±30 s of clock drift) plus an extra
 * window so server/client skew never locks a legitimate person out.
 */
export function verifyTotp(secretBase32, code, { stepSeconds = 30, window = 1, now = Date.now() } = {}) {
  if (!/^\d{6}$/.test(String(code ?? '').trim())) return false;
  const secretBytes = base32Decode(secretBase32);
  const counter = Math.floor(now / 1000 / stepSeconds);
  for (let drift = -window; drift <= window; drift++) {
    if (hotp(secretBytes, counter + drift) === String(code).trim()) return true;
  }
  return false;
}

/** The otpauth:// provisioning URI authenticators encode as a QR code. */
export function provisioningUri(secretBase32, accountName, issuer = 'DSH') {
  const label = encodeURIComponent(issuer) + ':' + encodeURIComponent(accountName);
  // SHA1/6-digit/30s are the universal defaults; naming them is optional and
  // the short URI keeps the QR small.
  const query = new URLSearchParams({ secret: secretBase32, issuer });
  return 'otpauth://totp/' + label + '?' + query.toString();
}
