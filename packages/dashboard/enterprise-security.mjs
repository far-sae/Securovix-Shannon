import crypto from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function masterKey() {
  if (process.env.NODE_ENV === 'production' && (String(process.env.SHANNON_ENCRYPTION_KEY || '').length < 32 || /replace-me|change-me/i.test(process.env.SHANNON_ENCRYPTION_KEY || ''))) {
    throw new Error('SHANNON_ENCRYPTION_KEY must be a non-placeholder value of at least 32 characters in production');
  }
  const source = process.env.SHANNON_ENCRYPTION_KEY || process.env.SHANNON_SESSION_SECRET || '';
  return crypto
    .createHash('sha256')
    .update(source || 'shannon-local-development-key')
    .digest();
}

export function encryptSecret(value) {
  if (value == null || value === '') return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

export function decryptSecret(value) {
  if (!value) return null;
  const [version, iv, tag, ciphertext] = String(value).split('.');
  if (version !== 'v1' || !iv || !tag || !ciphertext) throw new Error('invalid encrypted secret');
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  const plain = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function hashToken(token) {
  return crypto
    .createHash('sha256')
    .update(String(token || ''))
    .digest('hex');
}

export function signChallenge(payload, purpose, ttlMs = 10 * 60_000) {
  const body = Buffer.from(JSON.stringify({ ...payload, purpose, exp: Date.now() + ttlMs })).toString('base64url');
  const sig = crypto.createHmac('sha256', masterKey()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

export function verifyChallenge(token, purpose) {
  const [body, signature] = String(token || '').split('.');
  if (!body || !signature) return null;
  const expected = crypto.createHmac('sha256', masterKey()).update(body).digest('base64url');
  if (expected.length !== signature.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature)))
    return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.purpose !== purpose || !payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function base32Encode(input) {
  let bits = '';
  for (const byte of input) bits += byte.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    out += B32[Number.parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  }
  return out;
}

function base32Decode(input) {
  let bits = '';
  for (const char of String(input || '')
    .toUpperCase()
    .replace(/=|\s|-/g, '')) {
    const at = B32.indexOf(char);
    if (at < 0) throw new Error('invalid base32 secret');
    bits += at.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function hotp(secret, counter) {
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(counterBytes).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const number = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(number).padStart(6, '0');
}

export function newTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

export function totpCode(secret, now = Date.now()) {
  return hotp(secret, Math.floor(now / 30_000));
}

export function verifyTotp(secret, code, now = Date.now()) {
  const candidate = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(candidate)) return false;
  for (const offset of [-1, 0, 1]) {
    const expected = hotp(secret, Math.floor(now / 30_000) + offset);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(candidate))) return true;
  }
  return false;
}

export function totpUri({ secret, email, issuer = 'Securovix Shannon' }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function createRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => {
    const raw = crypto.randomBytes(8).toString('hex');
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12)}`;
  });
}

export function hashRecoveryCodes(codes) {
  return (codes || []).map(hashToken);
}

export function consumeRecoveryCode(code, hashes) {
  const wanted = hashToken(String(code || '').toLowerCase());
  const index = (hashes || []).findIndex((hash) => {
    try {
      return hash.length === wanted.length && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(wanted));
    } catch {
      return false;
    }
  });
  if (index < 0) return null;
  return hashes.filter((_, at) => at !== index);
}

export function publicBaseUrl(req) {
  const configured = String(process.env.SHANNON_PUBLIC_URL || '').replace(/\/$/, '');
  return configured || `${req.protocol}://${req.get('host')}`;
}
