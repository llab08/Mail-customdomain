// Security helpers: public/private domains, password hashing, per-IP
// failure limits and the per-request token re-check.

// ---------------------------------------------------------------- domains

export function parseDomainList(value: string | undefined | null): string[] {
  return String(value || '')
    .split(/[\s,]+/)
    .map(d => d.trim().toLowerCase())
    .filter(Boolean);
}

export function privateDomains(env: { PRIVATE_DOMAINS?: string }): string[] {
  return parseDomainList(env.PRIVATE_DOMAINS);
}

/** Domains anyone may create accounts on. A domain listed as private is never public. */
export function publicDomains(env: { MAIL_DOMAIN?: string; PRIVATE_DOMAINS?: string }): string[] {
  const priv = privateDomains(env);
  return parseDomainList(env.MAIL_DOMAIN).filter(d => !isDomainIn(d, priv));
}

function isDomainIn(domain: string, list: string[]): boolean {
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return false;
  return list.some(p => d === p || d.endsWith('.' + p));
}

export function normalizeAddress(address: unknown): string {
  return String(address ?? '').trim().toLowerCase();
}

/** Domain after the last '@' (the part mail is actually routed on). */
export function domainOfAddress(address: unknown): string {
  const a = normalizeAddress(address);
  const at = a.lastIndexOf('@');
  return at === -1 ? '' : a.slice(at + 1);
}

export function isPrivateAddress(env: { PRIVATE_DOMAINS?: string }, address: unknown): boolean {
  return isDomainIn(domainOfAddress(address), privateDomains(env));
}

/** Strict split used for new accounts: exactly one '@', both sides non-empty. */
export function splitAddress(address: unknown): { local: string; domain: string } | null {
  const a = normalizeAddress(address);
  const parts = a.split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  return { local: parts[0], domain: parts[1] };
}

// ------------------------------------------------------------- passwords

export const PBKDF2_PREFIX = 'pbkdf2-sha256';
/** Workers' WebCrypto refuses PBKDF2 above 100,000 iterations. */
export const PBKDF2_MAX_ITERATIONS = 100000;
/**
 * Iterations for temp-mail account passwords. Kept low enough that account
 * creation and login stay a few milliseconds of CPU on the Workers free plan;
 * still salted and far slower to brute-force than the legacy bare SHA-256.
 */
export const USER_PBKDF2_ITERATIONS = 20000;

const encoder = new TextEncoder();

export function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(String(text || '')));
  return bytesToHex(new Uint8Array(digest));
}

/** Constant-time comparison of two byte arrays / strings. */
export function timingSafeEqual(a: Uint8Array | string, b: Uint8Array | string): boolean {
  const x = typeof a === 'string' ? encoder.encode(a) : a;
  const y = typeof b === 'string' ? encoder.encode(b) : b;
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number, bytes: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    bytes * 8
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string, iterations: number = USER_PBKDF2_ITERATIONS): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(String(password), salt, iterations, 32);
  return `${PBKDF2_PREFIX}$${iterations}$${bytesToB64(salt)}$${bytesToB64(hash)}`;
}

export function isLegacyHash(stored: unknown): boolean {
  return typeof stored === 'string' && /^[0-9a-f]{64}$/i.test(stored);
}

/**
 * Verifies a password against either format:
 *  - pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>
 *  - legacy unsalted SHA-256 hex (what the Worker stored before this change)
 */
export async function verifyPassword(password: string, stored: unknown): Promise<boolean> {
  if (typeof stored !== 'string' || !stored) return false;
  if (isLegacyHash(stored)) {
    return timingSafeEqual(await sha256Hex(password), stored.toLowerCase());
  }
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== PBKDF2_PREFIX) return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1) return false;
  if (iterations > PBKDF2_MAX_ITERATIONS) {
    console.error(`PBKDF2 hash uses ${iterations} iterations; Workers supports at most ${PBKDF2_MAX_ITERATIONS}.`);
    return false;
  }
  let salt: Uint8Array;
  let expected: Uint8Array;
  try {
    salt = b64ToBytes(parts[2]);
    expected = b64ToBytes(parts[3]);
  } catch (_) {
    return false;
  }
  if (!salt.length || expected.length < 16) return false;
  const actual = await pbkdf2(String(password), salt, iterations, expected.length);
  return timingSafeEqual(actual, expected);
}

// ------------------------------------------------------ failure limits

export interface FailureRule {
  key: string;     // logical key, hashed before it is stored
  limit: number;   // failures allowed inside the window
}

export const FAILURE_WINDOW_SECONDS = 15 * 60;
/**
 * Expired counter rows deleted per attempt at most. Each attempt adds at most
 * one row per rule, so this keeps up while keeping every cleanup small (it
 * reads through idx_auth_failures_window_start, never the whole table).
 */
export const EXPIRED_ROWS_PER_CLEANUP = 50;

/** Created by the schema setup (database.js), together with the window_start index. */
export async function ensureAuthFailuresTable(db: D1Database): Promise<void> {
  await db.exec(
    'CREATE TABLE IF NOT EXISTS auth_failures (key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL)'
  );
}

async function storageKey(key: string): Promise<string> {
  // Only a hash is stored, so the table never holds raw IPs or addresses.
  return sha256Hex('auth-failure:' + key);
}

/** The address Cloudflare saw the request come from. */
export function clientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

/** Expands an IPv6 address to its 8 hextets, or returns null when it is not one. */
function ipv6Hextets(ip: string): number[] | null {
  let s = ip.trim().toLowerCase();
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  if (!/^[0-9a-f:.]+$/.test(s) || !s.includes(':')) return null;
  // An embedded IPv4 tail (::ffff:192.0.2.1) becomes two hextets.
  const v4 = s.match(/^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const b = v4.slice(2).map(Number);
    if (b.some(x => x > 255)) return null;
    s = v4[1] + ((b[0] << 8) | b[1]).toString(16) + ':' + ((b[2] << 8) | b[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string) => (part ? part.split(':') : []);
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (all.some(h => !/^[0-9a-f]{1,4}$/.test(h))) return null;
  return all.map(h => parseInt(h, 16));
}

/**
 * The key failure limits count per client: the whole address for IPv4, the
 * /64 prefix for IPv6 (one end user usually holds a whole /64, so counting per
 * address would give them a fresh allowance on every address in it).
 */
export function rateKeyForIp(ip: string): string {
  const h = ipv6Hextets(ip);
  if (!h) return String(ip || 'unknown').trim().toLowerCase() || 'unknown';
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    // IPv4-mapped IPv6: count it like the IPv4 address it carries.
    return `${h[6] >> 8}.${h[6] & 255}.${h[7] >> 8}.${h[7] & 255}`;
  }
  return h.slice(0, 4).map(x => x.toString(16)).join(':') + '::/64';
}

/** Headers the DuckMail web app's /api/mail proxy adds (see app/api/mail/route.ts). */
export const CLIENT_IP_HEADER = 'X-DuckMail-Client-IP';
export const CLIENT_IP_SIGNATURE_HEADER = 'X-DuckMail-Client-IP-Signature';
/** How old a signed client-IP header may be (clock skew included). */
export const CLIENT_IP_MAX_AGE_SECONDS = 300;
const MIN_CLIENT_IP_SECRET_LENGTH = 32;

/** HMAC-SHA256 over "v1.<unix seconds>.<ip>", base64url, as the proxy computes it. */
export async function signClientIp(secret: string, ip: string, ts: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(`v1.${ts}.${ip}`)));
  return `v1.${ts}.` + bytesToB64(sig).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * The client IP that failure limits are counted on.
 *
 * The DuckMail web app calls this Worker from its own server, so for web-app
 * users CF-Connecting-IP is the app server's address, shared by everyone.
 * The app therefore passes the browser's IP in X-DuckMail-Client-IP, signed
 * with the shared secret CLIENT_IP_SECRET (HMAC over timestamp and IP). The
 * header is used only when that signature is valid and fresh; anything else
 * (no secret configured, no header, bad or old signature) falls back to
 * CF-Connecting-IP, so a caller cannot choose its own IP.
 */
export async function limitClientIp(request: Request, env: { CLIENT_IP_SECRET?: string }, now: number = nowSeconds()): Promise<string> {
  const direct = clientIp(request);
  const secret = env.CLIENT_IP_SECRET;
  if (typeof secret !== 'string' || secret.length < MIN_CLIENT_IP_SECRET_LENGTH) return direct;
  const claimed = (request.headers.get(CLIENT_IP_HEADER) || '').trim();
  const signature = (request.headers.get(CLIENT_IP_SIGNATURE_HEADER) || '').trim();
  if (!claimed || !signature || claimed.length > 64 || !/^[0-9A-Fa-f:.]+$/.test(claimed)) return direct;
  const m = signature.match(/^v1\.(\d{1,12})\.[A-Za-z0-9_-]{43}$/);
  if (!m) return direct;
  const ts = Number(m[1]);
  if (Math.abs(now - ts) > CLIENT_IP_MAX_AGE_SECONDS) return direct;
  const expected = await signClientIp(secret, claimed, ts);
  return timingSafeEqual(expected, signature) ? claimed : direct;
}

/**
 * Counts one attempt against every rule BEFORE the password is checked, in
 * one D1 batch (an atomic transaction), and returns the seconds to wait when
 * any rule is over its limit (0 = go ahead). Because the counter is taken
 * first, parallel requests cannot all pass a "check, then record" gap.
 *
 * The caller settles every allowed attempt: on success with
 * settleAttempt(db, rules, clearKeys) (the attempt is refunded, so only
 * failures stay counted), on failure by doing nothing. A refused (429)
 * attempt is refunded here, so the counter holds failures plus attempts
 * still in flight.
 */
export async function takeAttempt(db: D1Database, rules: FailureRule[], now: number = nowSeconds()): Promise<number> {
  const expired = now - FAILURE_WINDOW_SECONDS;
  const keys = await Promise.all(rules.map(r => storageKey(r.key)));
  const results = await db.batch<{ count: number; window_start: number }>([
    // Garbage collection of old windows, bounded and through the
    // window_start index (it used to delete, and read, the whole table).
    db.prepare(
      `DELETE FROM auth_failures WHERE rowid IN
         (SELECT rowid FROM auth_failures WHERE window_start <= ? ORDER BY window_start LIMIT ?)`
    ).bind(expired, EXPIRED_ROWS_PER_CLEANUP),
    ...keys.flatMap(key => [
      // This key's own expired window is always dropped first, so the limits
      // never depend on how far the bounded cleanup above got.
      db.prepare('DELETE FROM auth_failures WHERE key = ? AND window_start <= ?').bind(key, expired),
      db.prepare(
        `INSERT INTO auth_failures (key, count, window_start) VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET count = auth_failures.count + 1
         RETURNING count, window_start`
      ).bind(key, now),
    ]),
  ]);
  let wait = 0;
  rules.forEach((rule, i) => {
    const row = results[2 + 2 * i]?.results?.[0];
    if (!row) return;
    if (Number(row.count) > rule.limit) {
      wait = Math.max(wait, Number(row.window_start) + FAILURE_WINDOW_SECONDS - now, 1);
    }
  });
  if (wait > 0) await refund(db, keys);
  return wait;
}

async function refund(db: D1Database, hashedKeys: string[]): Promise<void> {
  if (!hashedKeys.length) return;
  await db.batch(hashedKeys.map(key =>
    db.prepare('UPDATE auth_failures SET count = max(count - 1, 0) WHERE key = ?').bind(key)));
}

/** A successful attempt: refunds it on every rule, and clears the rules in clearKeys entirely. */
export async function settleSuccess(db: D1Database, rules: FailureRule[], clearKeys: string[] = []): Promise<void> {
  const clear = new Set(clearKeys);
  const refundKeys = await Promise.all(rules.filter(r => !clear.has(r.key)).map(r => storageKey(r.key)));
  const clearHashed = await Promise.all([...clear].map(k => storageKey(k)));
  await db.batch([
    ...refundKeys.map(key => db.prepare('UPDATE auth_failures SET count = max(count - 1, 0) WHERE key = ?').bind(key)),
    ...clearHashed.map(key => db.prepare('DELETE FROM auth_failures WHERE key = ?').bind(key)),
  ]);
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ------------------------------------------------ user lookups / tokens

export interface UserRow {
  id: number;
  username: string;
  password_hash: string | null;
  role: string;
}

/**
 * Finds the login for an address. Matches on lower(trim(username)) (the
 * previous Worker stored usernames as typed; an expression index,
 * idx_users_username_norm, keeps this an index lookup). When old data holds
 * more than one row for the same address, the oldest row wins, so a
 * later-created duplicate can never take over an existing mailbox.
 */
export async function findUserByAddress(db: D1Database, address: unknown): Promise<UserRow | null> {
  const normalized = normalizeAddress(address);
  if (!normalized) return null;
  return db.prepare(
    'SELECT id, username, password_hash, role FROM users WHERE lower(trim(username)) = ? ORDER BY id ASC LIMIT 1'
  ).bind(normalized).first<UserRow>();
}

/** Role given to logins the admin creates for private-domain addresses. */
export const PRIVATE_ROLE = 'private';

/** A private-domain address may only be used by a login the admin created. */
export function userMayUseAddress(env: { PRIVATE_DOMAINS?: string }, user: { role?: string } | null, address: unknown): boolean {
  if (!user) return false;
  if (isPrivateAddress(env, address) && user.role !== PRIVATE_ROLE) return false;
  return true;
}

/**
 * Re-checks a verified JWT against the database on every request: the
 * token's user must still be the login for the token's address (the oldest
 * row for it), the token's mailbox must be that address's mailbox, and
 * private-domain mailboxes need an admin-created login. This revokes tokens
 * issued before a user was deleted, re-created or blocked.
 */
export async function tokenStillValid(env: { TEMP_MAIL_DB: D1Database; PRIVATE_DOMAINS?: string }, payload: any): Promise<boolean> {
  if (!payload || typeof payload !== 'object') return false;
  const normalized = normalizeAddress(payload.address);
  if (!normalized) return false;
  const row = await env.TEMP_MAIL_DB.prepare(
    `SELECT u.id AS user_id, u.role AS role, (SELECT m.id FROM mailboxes m WHERE m.address = ?) AS mailbox_id
       FROM users u
      WHERE lower(trim(u.username)) = ?
      ORDER BY u.id ASC LIMIT 1`
  ).bind(normalized, normalized).first<{ user_id: number; role: string; mailbox_id: number | null }>();
  if (!row || row.mailbox_id == null) return false;
  if (Number(row.user_id) !== Number(payload.userId)) return false;
  if (Number(row.mailbox_id) !== Number(payload.mailboxId)) return false;
  if (!userMayUseAddress(env, { role: row.role }, normalized)) return false;
  return true;
}

// ------------------------------------------------------------ forwarding

/**
 * FORWARD_RULES: JSON object mapping a full recipient address to a verified
 * Email Routing destination, e.g. {"hello@example.com":"me@example.net"}.
 * Empty or invalid → no forwarding.
 */
export function forwardTarget(env: { FORWARD_RULES?: string }, toAddress: unknown): string | null {
  const raw = String(env.FORWARD_RULES || '').trim();
  if (!raw) return null;
  let rules: unknown;
  try {
    rules = JSON.parse(raw);
  } catch (_) {
    console.error('FORWARD_RULES is not valid JSON; forwarding disabled');
    return null;
  }
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) return null;
  const want = normalizeAddress(toAddress);
  for (const [from, to] of Object.entries(rules as Record<string, unknown>)) {
    if (normalizeAddress(from) === want && typeof to === 'string' && to.includes('@')) return to.trim();
  }
  return null;
}
