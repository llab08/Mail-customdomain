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

export async function ensureAuthFailuresTable(db: D1Database): Promise<void> {
  await db.exec(
    'CREATE TABLE IF NOT EXISTS auth_failures (key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL)'
  );
}

async function storageKey(key: string): Promise<string> {
  // Only a hash is stored, so the table never holds raw IPs or addresses.
  return sha256Hex('auth-failure:' + key);
}

export function clientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

/** Returns seconds until the oldest blocking window ends, or 0 when allowed. */
export async function blockedFor(db: D1Database, rules: FailureRule[], now: number = nowSeconds()): Promise<number> {
  await ensureAuthFailuresTable(db);
  let wait = 0;
  for (const rule of rules) {
    const row = await db.prepare('SELECT count, window_start FROM auth_failures WHERE key = ?')
      .bind(await storageKey(rule.key)).first<{ count: number; window_start: number }>();
    if (!row) continue;
    const ends = Number(row.window_start) + FAILURE_WINDOW_SECONDS;
    if (ends > now && Number(row.count) >= rule.limit) wait = Math.max(wait, ends - now);
  }
  return wait;
}

export async function recordFailure(db: D1Database, rules: FailureRule[], now: number = nowSeconds()): Promise<void> {
  await ensureAuthFailuresTable(db);
  const expired = now - FAILURE_WINDOW_SECONDS;
  for (const rule of rules) {
    await db.prepare(
      `INSERT INTO auth_failures (key, count, window_start) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN auth_failures.window_start <= ? THEN 1 ELSE auth_failures.count + 1 END,
         window_start = CASE WHEN auth_failures.window_start <= ? THEN excluded.window_start ELSE auth_failures.window_start END`
    ).bind(await storageKey(rule.key), now, expired, expired).run();
  }
  await db.prepare('DELETE FROM auth_failures WHERE window_start <= ?').bind(expired).run();
}

export async function clearFailures(db: D1Database, keys: string[]): Promise<void> {
  await ensureAuthFailuresTable(db);
  for (const key of keys) {
    await db.prepare('DELETE FROM auth_failures WHERE key = ?').bind(await storageKey(key)).run();
  }
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

/** Finds the user for an address. Usernames are stored lower-cased; the raw form is a fallback. */
export async function findUserByAddress(db: D1Database, address: unknown): Promise<UserRow | null> {
  const raw = String(address ?? '').trim();
  const normalized = normalizeAddress(address);
  if (!normalized) return null;
  return db.prepare(
    'SELECT id, username, password_hash, role FROM users WHERE username IN (?, ?) ORDER BY (username = ?) DESC LIMIT 1'
  ).bind(normalized, raw, normalized).first<UserRow>();
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
 * Re-checks a verified JWT against the database on every request: the user
 * must still exist with the same id, the token's mailbox must be that user's
 * mailbox, and private-domain mailboxes need an admin-created login. This
 * revokes tokens issued before a user was deleted or blocked.
 */
export async function tokenStillValid(env: { TEMP_MAIL_DB: D1Database; PRIVATE_DOMAINS?: string }, payload: any): Promise<boolean> {
  if (!payload || typeof payload !== 'object') return false;
  const raw = String(payload.address ?? '').trim();
  const normalized = normalizeAddress(payload.address);
  if (!normalized) return false;
  const row = await env.TEMP_MAIL_DB.prepare(
    `SELECT u.id AS user_id, u.role AS role, m.id AS mailbox_id, m.address AS mailbox_address
       FROM users u LEFT JOIN mailboxes m ON m.address = lower(trim(u.username))
      WHERE u.username IN (?, ?)
      ORDER BY (u.username = ?) DESC LIMIT 1`
  ).bind(normalized, raw, normalized).first<{ user_id: number; role: string; mailbox_id: number | null; mailbox_address: string | null }>();
  if (!row || row.mailbox_id == null) return false;
  if (Number(row.user_id) !== Number(payload.userId)) return false;
  if (Number(row.mailbox_id) !== Number(payload.mailboxId)) return false;
  if (!userMayUseAddress(env, { role: row.role }, row.mailbox_address)) return false;
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
