// Shared helpers for the Worker tests. Everything runs against the local
// Workers runtime and a local, empty D1 database (see vitest.config.mts).
import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { vi } from 'vitest';
import worker from '../worker';
import { createJwt } from '../authentication.js';
import { initDatabase, getOrCreateMailboxId } from '../database.js';
import { sha256Hex } from '../security';

export const E: any = env;
export const ORIGIN = 'https://worker.test';
export const ADMIN_PASSWORD: string = E.TEST_ADMIN_PASSWORD;

export interface CallOptions {
  body?: unknown;
  form?: Record<string, string>;
  token?: string;
  ip?: string;
  cookie?: string;
  origin?: string | null;
  headers?: Record<string, string>;
  env?: any;
}

export async function call(method: string, path: string, opts: CallOptions = {}): Promise<Response> {
  const headers = new Headers(opts.headers || {});
  headers.set('CF-Connecting-IP', opts.ip || '203.0.113.10');
  let body: BodyInit | undefined;
  if (opts.form) {
    body = new URLSearchParams(opts.form).toString();
    headers.set('Content-Type', 'application/x-www-form-urlencoded');
  } else if (opts.body !== undefined) {
    body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
    headers.set('Content-Type', 'application/json');
  }
  if (opts.token) headers.set('Authorization', 'Bearer ' + opts.token);
  if (opts.cookie) headers.set('Cookie', opts.cookie);
  if (opts.origin !== undefined && opts.origin !== null) headers.set('Origin', opts.origin);
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(ORIGIN + path, { method, headers, body, redirect: 'manual' }) as any, opts.env || E, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export async function json(res: Response): Promise<any> {
  return JSON.parse(await res.text());
}

export async function createAccount(address: string, password: string): Promise<Response> {
  return call('POST', '/accounts', { body: { address, password } });
}

export async function getToken(address: string, password: string, ip?: string): Promise<Response> {
  return call('POST', '/token', { body: { address, password }, ip });
}

export async function tokenFor(address: string, password: string): Promise<string> {
  const res = await getToken(address, password);
  if (res.status !== 200) throw new Error(`token for ${address}: HTTP ${res.status}`);
  return (await json(res)).token;
}

export interface FakeMail {
  from?: string;
  to: string;
  subject?: string;
  text?: string;
  html?: string;
  forward?: (to: string) => Promise<void>;
}

/** Delivers a message through the Worker's email() handler, like Email Routing does. */
export async function deliver(mail: FakeMail) {
  const subject = mail.subject ?? 'Hello';
  const from = mail.from ?? 'sender@example.com';
  let raw: string;
  if (mail.html) {
    raw = [
      `From: ${from}`, `To: ${mail.to}`, `Subject: ${subject}`,
      'MIME-Version: 1.0', 'Content-Type: multipart/alternative; boundary="b1"', '',
      '--b1', 'Content-Type: text/plain; charset=utf-8', '', mail.text ?? 'plain part',
      '--b1', 'Content-Type: text/html; charset=utf-8', '', mail.html,
      '--b1--', '',
    ].join('\r\n');
  } else {
    raw = [`From: ${from}`, `To: ${mail.to}`, `Subject: ${subject}`, 'Content-Type: text/plain; charset=utf-8', '', mail.text ?? 'body text', ''].join('\r\n');
  }
  const forward = vi.fn(mail.forward || (async () => {}));
  const message = { from, to: mail.to, raw, headers: new Headers({ subject }), rawSize: raw.length, forward };
  const ctx = createExecutionContext();
  await (worker as any).email(message, E, ctx);
  await waitOnExecutionContext(ctx);
  return { forward };
}

/** Inserts a user the way the previous Worker did (unsalted SHA-256), with its mailbox. */
export async function seedLegacyUser(address: string, password: string, role = 'user') {
  await initDatabase(E.TEMP_MAIL_DB);
  const mailboxId = await getOrCreateMailboxId(E.TEMP_MAIL_DB, address);
  await E.TEMP_MAIL_DB.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    .bind(address, await sha256Hex(password), role).run();
  const user = await E.TEMP_MAIL_DB.prepare('SELECT id FROM users WHERE username = ?').bind(address).first();
  return { mailboxId: Number(mailboxId), userId: Number(user.id) };
}

/** A JWT exactly like the previous Worker issued (same secret, same claims). */
export async function legacyJwt(address: string, mailboxId: number, userId: number): Promise<string> {
  return createJwt(E.JWT_SECRET, { address, mailboxId, userId });
}

export async function query<T = any>(sql: string, ...binds: unknown[]): Promise<T[]> {
  return ((await E.TEMP_MAIL_DB.prepare(sql).bind(...binds).all()).results || []) as T[];
}

// ------------------------------------------------------------- admin

export function cookieFrom(res: Response): string {
  const set = res.headers.get('Set-Cookie') || '';
  return set.split(';')[0];
}

export async function adminLogin(ip?: string): Promise<string> {
  const res = await call('POST', '/admin/login', { form: { password: ADMIN_PASSWORD }, origin: ORIGIN, ip });
  if (res.status !== 303) throw new Error('admin login failed: HTTP ' + res.status);
  return cookieFrom(res);
}

export async function csrfFrom(cookie: string, path = '/admin'): Promise<string> {
  const html = await (await call('GET', path, { cookie })).text();
  const m = html.match(/name="csrf" value="([^"]+)"/);
  if (!m) throw new Error('no csrf token on ' + path);
  return m[1];
}
