// Admin portal under /admin: one admin password, a signed session cookie,
// and pages to read and delete mail of the private domains.
//
// Every value put into HTML goes through esc(). Email HTML is never inlined:
// it is served by /admin/message/html with a sandbox CSP and embedded in an
// <iframe sandbox>. No page uses scripts.

import { getOrCreateMailboxId } from './database.js';
import {
  PBKDF2_PREFIX,
  PRIVATE_ROLE,
  USER_PBKDF2_ITERATIONS,
  bytesToB64,
  clientIp,
  forwardTarget,
  hashPassword,
  isPrivateAddress,
  normalizeAddress,
  nowSeconds,
  privateDomains,
  rateKeyForIp,
  settleSuccess,
  sha256Hex,
  splitAddress,
  takeAttempt,
  timingSafeEqual,
  verifyPassword,
} from './security';

export interface AdminEnv {
  TEMP_MAIL_DB: D1Database;
  PRIVATE_DOMAINS?: string;
  ADMIN_PASSWORD_HASH?: string;
  ADMIN_SESSION_SECRET?: string;
  FORWARD_RULES?: string;
}

export const ADMIN_COOKIE = 'duckmail_admin';
export const ADMIN_SESSION_SECONDS = 12 * 60 * 60;
/** Failed admin logins allowed per 15 minutes from one IPv4 address or IPv6 /64. */
export const ADMIN_LOGIN_FAILURE_LIMIT = 10;
/**
 * Failed admin logins allowed per 15 minutes from all sources together. Stops
 * guessing spread over many IPs; the price is that someone who sends this
 * many wrong passwords locks the login page for everyone until the window
 * ends (signed-in sessions keep working). The owner can end the lock early:
 * npx wrangler d1 execute temp_mail_db --remote --command "DELETE FROM auth_failures"
 */
export const ADMIN_LOGIN_GLOBAL_FAILURE_LIMIT = 30;
const MIN_APP_PASSWORD_LENGTH = 12;
const MESSAGES_PER_PAGE = 50;
const MAILBOXES_PER_PAGE = 100;

const PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
export const EMAIL_HTML_CSP =
  "sandbox; default-src 'none'; img-src data: https:; style-src 'unsafe-inline'; frame-ancestors 'self'";

// ------------------------------------------------------------------ entry

export async function handleAdmin(request: Request, env: AdminEnv): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/admin';
  const method = request.method;

  if (!adminConfigured(env)) {
    return page('Admin not configured', `<h1>Admin portal is not configured</h1>
      <p>Set the Worker secrets <code>ADMIN_PASSWORD_HASH</code> and <code>ADMIN_SESSION_SECRET</code>.</p>`, 503);
  }

  if (method === 'POST') {
    // Strict Origin check on every state-changing request (login included).
    if (request.headers.get('Origin') !== url.origin) {
      return page('Forbidden', '<h1>Forbidden</h1><p>Cross-site request refused.</p>', 403);
    }
    if (path === '/admin/login') return login(request, env);
  }

  const session = await readSession(request, env);

  if (method === 'GET' && path === '/admin') {
    return session ? dashboard(env, session, url) : loginPage();
  }

  if (!session) {
    if (method === 'GET' && path === '/admin/message/html') {
      return new Response('Unauthorized', { status: 401, headers: emailHtmlHeaders() });
    }
    return method === 'GET' ? redirect('/admin') : page('Signed out', '<h1>Session expired</h1><p><a href="/admin">Sign in again</a></p>', 401);
  }

  if (method === 'GET') {
    if (path === '/admin/mailbox') return mailboxPage(env, session, url);
    if (path === '/admin/message') return messagePage(env, session, url);
    if (path === '/admin/message/html') return messageHtml(env, url);
  }

  if (method === 'POST') {
    let form: FormData;
    try {
      form = await request.formData();
    } catch (_) {
      return page('Bad request', '<h1>Bad request</h1><p><a href="/admin">Back</a></p>', 400);
    }
    const csrf = String(form.get('csrf') || '');
    if (!timingSafeEqual(csrf, session.csrf)) {
      return page('Forbidden', '<h1>Forbidden</h1><p>Invalid form token. Reload the page and try again.</p>', 403);
    }
    if (path === '/admin/logout') return logout();
    if (path === '/admin/message/delete') return deleteMessage(env, form);
    if (path === '/admin/mailbox/delete') return deleteMailbox(env, form);
    if (path === '/admin/users/delete') return deleteUser(env, form);
    if (path === '/admin/users/create') return createPrivateLogin(env, form);
  }

  return page('Not found', '<h1>Not found</h1><p><a href="/admin">Back</a></p>', 404);
}

export function adminConfigured(env: AdminEnv): boolean {
  return typeof env.ADMIN_PASSWORD_HASH === 'string'
    && env.ADMIN_PASSWORD_HASH.startsWith(PBKDF2_PREFIX + '$')
    && typeof env.ADMIN_SESSION_SECRET === 'string'
    && env.ADMIN_SESSION_SECRET.length >= 32;
}

// ---------------------------------------------------------------- session

interface Session {
  exp: number;
  nonce: string;
  csrf: string;
}

const enc = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlToString(s: string): string {
  let t = s.replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  return atob(t);
}

async function hmacKey(env: AdminEnv): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(String(env.ADMIN_SESSION_SECRET)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function hmac(env: AdminEnv, data: string): Promise<string> {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(data));
  return b64url(new Uint8Array(sig));
}

/** Changing ADMIN_PASSWORD_HASH invalidates every session. */
async function passwordVersion(env: AdminEnv): Promise<string> {
  return (await sha256Hex(String(env.ADMIN_PASSWORD_HASH))).slice(0, 16);
}

async function createSessionCookie(env: AdminEnv): Promise<string> {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(18)));
  const body = b64url(enc.encode(JSON.stringify({
    exp: nowSeconds() + ADMIN_SESSION_SECONDS,
    nonce,
    pv: await passwordVersion(env),
  })));
  const value = body + '.' + (await hmac(env, 'session.' + body));
  return `${ADMIN_COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=${ADMIN_SESSION_SECONDS}`;
}

function clearedCookie(): string {
  return `${ADMIN_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=0`;
}

async function readSession(request: Request, env: AdminEnv): Promise<Session | null> {
  const cookies = request.headers.get('Cookie') || '';
  const prefix = ADMIN_COOKIE + '=';
  const found = cookies.split(';').map(c => c.trim()).find(c => c.startsWith(prefix));
  if (!found) return null;
  const [body, sig, extra] = found.slice(prefix.length).split('.');
  if (!body || !sig || extra !== undefined) return null;
  if (!timingSafeEqual(sig, await hmac(env, 'session.' + body))) return null;
  try {
    const data = JSON.parse(b64urlToString(body));
    if (typeof data.exp !== 'number' || data.exp <= nowSeconds()) return null;
    if (data.pv !== (await passwordVersion(env))) return null;
    if (typeof data.nonce !== 'string' || !data.nonce) return null;
    return { exp: data.exp, nonce: data.nonce, csrf: await hmac(env, 'csrf.' + data.nonce) };
  } catch (_) {
    return null;
  }
}

// ------------------------------------------------------------ login/out

async function login(request: Request, env: AdminEnv): Promise<Response> {
  // The attempt is counted atomically before the (costly) password check, so
  // parallel requests cannot exceed the limits; a success is refunded.
  const ipRule = { key: 'admin-login:' + rateKeyForIp(clientIp(request)), limit: ADMIN_LOGIN_FAILURE_LIMIT };
  const rules = [ipRule, { key: 'admin-login:all', limit: ADMIN_LOGIN_GLOBAL_FAILURE_LIMIT }];
  const wait = await takeAttempt(env.TEMP_MAIL_DB, rules);
  if (wait > 0) {
    return loginPage('Too many failed attempts. Try again in ' + Math.ceil(wait / 60) + ' min.', 429, { 'Retry-After': String(wait) });
  }
  let password = '';
  try {
    password = String((await request.formData()).get('password') || '');
  } catch (_) { /* treated as a wrong password */ }
  const ok = password.length > 0 && password.length <= 1024
    && (await verifyPassword(password, env.ADMIN_PASSWORD_HASH));
  if (!ok) {
    // The attempt taken above stays counted as a failure.
    return loginPage('Wrong password.', 401);
  }
  await settleSuccess(env.TEMP_MAIL_DB, rules, [ipRule.key]);
  return redirect('/admin', { 'Set-Cookie': await createSessionCookie(env) });
}

function logout(): Response {
  return redirect('/admin', { 'Set-Cookie': clearedCookie() });
}

function loginPage(error = '', status = 200, extra: Record<string, string> = {}): Response {
  return page('Admin sign in', `
    <h1>DuckMail admin</h1>
    ${error ? `<p class="err" role="alert">${esc(error)}</p>` : ''}
    <form method="post" action="/admin/login" class="card">
      <label for="password">Admin password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Sign in</button>
    </form>`, status, extra);
}

// ------------------------------------------------------------------ pages

function privateAddressFilter(env: AdminEnv, column: string): { sql: string; binds: string[] } {
  const domains = privateDomains(env);
  if (!domains.length) return { sql: '0', binds: [] };
  const likeEsc = (s: string) => s.replace(/[\\%_]/g, c => '\\' + c);
  const parts: string[] = [];
  const binds: string[] = [];
  for (const d of domains) {
    parts.push(`${column} LIKE ? ESCAPE '\\'`, `${column} LIKE ? ESCAPE '\\'`);
    binds.push('%@' + likeEsc(d), '%@%.' + likeEsc(d));
  }
  return { sql: '(' + parts.join(' OR ') + ')', binds };
}

/** Private addresses that have a FORWARD_RULES entry (pinned on the dashboard). */
function forwardedPrivateAddresses(env: AdminEnv): string[] {
  const raw = String(env.FORWARD_RULES || '').trim();
  if (!raw) return [];
  let rules: unknown;
  try { rules = JSON.parse(raw); } catch (_) { return []; }
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) return [];
  return Object.keys(rules as Record<string, unknown>)
    .map(normalizeAddress)
    .filter(a => isPrivateAddress(env, a) && forwardTarget(env, a));
}

async function dashboard(env: AdminEnv, session: Session, url: URL): Promise<Response> {
  const db = env.TEMP_MAIL_DB;
  const q = normalizeAddress(url.searchParams.get('q') || '').slice(0, 200);
  const requestedPage = Math.max(1, Math.min(100000, parseInt(url.searchParams.get('page') || '1', 10) || 1));
  const likeEsc = (v: string) => v.replace(/[\\%_]/g, c => '\\' + c);

  const mf = privateAddressFilter(env, 'm.address');
  let where = mf.sql;
  const whereBinds: string[] = [...mf.binds];
  if (q) {
    where += " AND m.address LIKE ? ESCAPE '\\'";
    whereBinds.push('%' + likeEsc(q) + '%');
  }
  // Mailboxes with an app login or a forwarding rule come first, so real
  // addresses (hello@, ...) stay on page 1 however much catch-all spam
  // arrives; the rest by newest mail.
  //
  // Rows read per view: one pass over the mailbox addresses (the private
  // filter is a suffix LIKE), about three index rows per private mailbox
  // (newest via idx_messages_mailbox_received, login via
  // idx_users_username_norm), and the messages of the shown page only
  // (message_count is computed after LIMIT). The total comes from the same
  // pass (COUNT(*) OVER ()). "+m.address" makes the user lookups use the
  // expression index: compared with the TEXT column itself, SQLite cannot use
  // it and scanned every user for every private mailbox.
  const forwarded = forwardedPrivateAddresses(env);
  const pinSql = forwarded.length ? `OR m.address IN (${forwarded.map(() => '?').join(', ')})` : '';
  const pageOf = async (pageNo: number) => ((await db.prepare(
    `SELECT p.id, p.address, p.newest, p.login_role, p.total,
            (SELECT COUNT(*) FROM messages x WHERE x.mailbox_id = p.id) AS message_count
       FROM (SELECT m.id, m.address,
                    (SELECT MAX(x.received_at) FROM messages x WHERE x.mailbox_id = m.id) AS newest,
                    (SELECT u.role FROM users u WHERE lower(trim(u.username)) = +m.address ORDER BY u.id LIMIT 1) AS login_role,
                    (EXISTS (SELECT 1 FROM users u WHERE lower(trim(u.username)) = +m.address) ${pinSql}) AS pinned,
                    COUNT(*) OVER () AS total
               FROM mailboxes m
              WHERE ${where}
              ORDER BY pinned DESC, (newest IS NULL), newest DESC, m.id DESC
              LIMIT ? OFFSET ?) p
      ORDER BY p.pinned DESC, (p.newest IS NULL), p.newest DESC, p.id DESC`
  ).bind(...forwarded, ...whereBinds, MAILBOXES_PER_PAGE, (pageNo - 1) * MAILBOXES_PER_PAGE).all<any>()).results || []);

  let pageNo = requestedPage;
  let found = await pageOf(pageNo);
  let total = Number(found[0]?.total || 0);
  if (!found.length && pageNo > 1) {
    // Past the last page: count, then show the last page.
    total = Number((await db.prepare(`SELECT COUNT(*) AS c FROM mailboxes m WHERE ${where}`)
      .bind(...whereBinds).first<any>())?.c || 0);
    pageNo = Math.max(1, Math.ceil(total / MAILBOXES_PER_PAGE));
    if (total) found = await pageOf(pageNo);
  }
  const pages = Math.max(1, Math.ceil(total / MAILBOXES_PER_PAGE));
  const mailboxes = found.filter(r => isPrivateAddress(env, r.address));

  const uf = privateAddressFilter(env, 'u.username');
  const users = ((await db.prepare(
    `SELECT u.id, u.username, u.role, m.id AS mailbox_id
       FROM users u LEFT JOIN mailboxes m ON m.address = lower(trim(u.username))
      WHERE ${uf.sql}
      ORDER BY u.id DESC LIMIT 500`
  ).bind(...uf.binds).all<any>()).results || []).filter(r => isPrivateAddress(env, r.username));
  const leftovers = users.filter(u => u.role !== PRIVATE_ROLE);
  const logins = users.filter(u => u.role === PRIVATE_ROLE);

  const domainList = privateDomains(env).map(esc).join(', ') || '(none configured)';
  const forwardedSet = new Set(forwarded);
  const rows = mailboxes.map(m => `
    <tr>
      <td><a href="/admin/mailbox?id=${esc(m.id)}">${esc(m.address)}</a></td>
      <td class="num">${esc(m.message_count)}</td>
      <td>${esc(m.newest || '—')}</td>
      <td>${loginLabel(m.login_role)}${forwardedSet.has(m.address) ? ' · forwarded' : ''}</td>
    </tr>`).join('');
  // Escaped as a whole: esc() turns the '&' into '&amp;' for the attribute.
  const pageLink = (n: number) => esc('/admin?' + (q ? 'q=' + encodeURIComponent(q) + '&' : '') + 'page=' + n);
  const nav = pages > 1 ? `<p>
      ${pageNo > 1 ? `<a href="${pageLink(pageNo - 1)}">← previous</a>` : ''}
      page ${pageNo} of ${pages}
      ${pageNo < pages ? `<a href="${pageLink(pageNo + 1)}">next →</a>` : ''}</p>` : '';

  const leftoverRows = leftovers.map(u => `
    <tr>
      <td>${esc(u.username)}</td>
      <td>${esc(u.role)}</td>
      <td>${u.mailbox_id != null ? `<a href="/admin/mailbox?id=${esc(u.mailbox_id)}">open mailbox</a>` : 'no mailbox'}</td>
      <td>${postButton('/admin/users/delete', session, { id: u.id }, 'Delete login', true)}</td>
    </tr>`).join('');

  const loginRows = logins.map(u => `
    <tr>
      <td>${esc(u.username)}</td>
      <td>${postButton('/admin/users/delete', session, { id: u.id }, 'Remove app login', true)}</td>
    </tr>`).join('');

  return page('DuckMail admin', `
    ${header(session)}
    <p class="muted">Private domains: ${domainList}. Mail to these domains is stored but hidden from the public API.</p>

    <h2>Private mailboxes</h2>
    <form method="get" action="/admin" class="search">
      <label for="q">Find an address</label>
      <input id="q" name="q" type="search" value="${esc(q)}" placeholder="hello@" autocomplete="off">
      <button type="submit">Search</button>
      ${q ? '<a href="/admin">clear</a>' : ''}
    </form>
    <p class="muted">${esc(total)} mailbox(es)${q ? ' matching' : ''}. Mailboxes with an app login or a forwarding rule are listed first.</p>
    ${mailboxes.length ? `<div class="scroll"><table>
      <thead><tr><th>Address</th><th class="num">Messages</th><th>Newest</th><th>App login</th></tr></thead>
      <tbody>${rows}</tbody></table></div>${nav}` : `<p class="muted">${q ? 'No mailbox matches.' : 'No mail received yet.'}</p>`}

    <h2>Blocked leftovers</h2>
    <p class="muted">Logins on private domains that were created through the public API. They can no longer sign in; delete them to clean up.</p>
    ${leftovers.length ? `<div class="scroll"><table>
      <thead><tr><th>Address</th><th>Role</th><th>Mailbox</th><th></th></tr></thead>
      <tbody>${leftoverRows}</tbody></table></div>` : '<p class="muted">None.</p>'}

    <h2>App logins for private addresses</h2>
    ${logins.length ? `<div class="scroll"><table>
      <thead><tr><th>Address</th><th></th></tr></thead><tbody>${loginRows}</tbody></table></div>` : '<p class="muted">None. Private mail is only readable here.</p>'}
    <details class="card">
      <summary>Create an app login</summary>
      <p class="muted">Lets someone read one private address in the DuckMail app. Replaces any existing login for that address.</p>
      <form method="post" action="/admin/users/create">
        ${csrfField(session)}
        <label for="addr">Address</label>
        <input id="addr" name="address" type="email" required placeholder="name@${esc(privateDomains(env)[0] || 'example.com')}">
        <label for="pw">Password (at least ${MIN_APP_PASSWORD_LENGTH} characters)</label>
        <input id="pw" name="password" type="password" minlength="${MIN_APP_PASSWORD_LENGTH}" autocomplete="new-password" required>
        <button type="submit">Create login</button>
      </form>
    </details>`);
}

async function loadPrivateMailbox(env: AdminEnv, id: unknown): Promise<{ id: number; address: string } | null> {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return null;
  const mb = await env.TEMP_MAIL_DB.prepare('SELECT id, address FROM mailboxes WHERE id = ?').bind(n).first<{ id: number; address: string }>();
  return mb && isPrivateAddress(env, mb.address) ? mb : null;
}

async function loadPrivateMessage(env: AdminEnv, id: unknown): Promise<any | null> {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return null;
  const msg = await env.TEMP_MAIL_DB.prepare(
    `SELECT msg.id, msg.mailbox_id, msg.sender, msg.subject, msg.content, msg.html_content, msg.received_at, m.address
       FROM messages msg JOIN mailboxes m ON m.id = msg.mailbox_id WHERE msg.id = ?`
  ).bind(n).first<any>();
  return msg && isPrivateAddress(env, msg.address) ? msg : null;
}

async function mailboxPage(env: AdminEnv, session: Session, url: URL): Promise<Response> {
  const mb = await loadPrivateMailbox(env, url.searchParams.get('id'));
  if (!mb) return page('Not found', '<h1>Mailbox not found</h1><p><a href="/admin">Back</a></p>', 404);
  const db = env.TEMP_MAIL_DB;
  const pageNo = Math.max(1, Math.min(10000, parseInt(url.searchParams.get('page') || '1', 10) || 1));
  const total = Number((await db.prepare('SELECT COUNT(*) AS c FROM messages WHERE mailbox_id = ?').bind(mb.id).first<any>())?.c || 0);
  const msgs = (await db.prepare(
    `SELECT id, sender, subject, received_at, length(content) + length(coalesce(html_content, '')) AS size
       FROM messages WHERE mailbox_id = ? ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?`
  ).bind(mb.id, MESSAGES_PER_PAGE, (pageNo - 1) * MESSAGES_PER_PAGE).all<any>()).results || [];
  const login = await db.prepare('SELECT id, role FROM users WHERE lower(trim(username)) = ? ORDER BY id LIMIT 1').bind(mb.address).first<any>();

  const rows = msgs.map(m => `
    <tr>
      <td>${esc(m.received_at)}</td>
      <td class="wrap">${esc(m.sender)}</td>
      <td class="wrap"><a href="/admin/message?id=${esc(m.id)}">${esc(m.subject || '(no subject)')}</a></td>
      <td class="num">${esc(m.size)}</td>
    </tr>`).join('');
  const pages = Math.max(1, Math.ceil(total / MESSAGES_PER_PAGE));
  const nav = pages > 1 ? `<p>
      ${pageNo > 1 ? `<a href="/admin/mailbox?id=${esc(mb.id)}&amp;page=${pageNo - 1}">← newer</a>` : ''}
      page ${pageNo} of ${pages}
      ${pageNo < pages ? `<a href="/admin/mailbox?id=${esc(mb.id)}&amp;page=${pageNo + 1}">older →</a>` : ''}</p>` : '';

  return page(mb.address, `
    ${header(session)}
    <p><a href="/admin">← All mailboxes</a></p>
    <h2 class="wrap">${esc(mb.address)}</h2>
    <p class="muted">${esc(total)} message(s). App login: ${loginLabel(login?.role)}</p>
    ${msgs.length ? `<div class="scroll"><table>
      <thead><tr><th>Received (UTC)</th><th>From</th><th>Subject</th><th class="num">Size</th></tr></thead>
      <tbody>${rows}</tbody></table></div>${nav}` : '<p class="muted">No messages.</p>'}
    <form method="post" action="/admin/mailbox/delete" class="card danger">
      ${csrfField(session)}
      <input type="hidden" name="id" value="${esc(mb.id)}">
      <label><input type="checkbox" name="confirm" value="yes" required> Delete this mailbox, all ${esc(total)} message(s) and its app login</label>
      <button type="submit">Delete mailbox</button>
    </form>`);
}

async function messagePage(env: AdminEnv, session: Session, url: URL): Promise<Response> {
  const msg = await loadPrivateMessage(env, url.searchParams.get('id'));
  if (!msg) return page('Not found', '<h1>Message not found</h1><p><a href="/admin">Back</a></p>', 404);
  const text = String(msg.content || '');
  return page(msg.subject || 'Message', `
    ${header(session)}
    <p><a href="/admin/mailbox?id=${esc(msg.mailbox_id)}">← ${esc(msg.address)}</a></p>
    <h2 class="wrap">${esc(msg.subject || '(no subject)')}</h2>
    <dl>
      <dt>From</dt><dd class="wrap">${esc(msg.sender)}</dd>
      <dt>To</dt><dd class="wrap">${esc(msg.address)}</dd>
      <dt>Received (UTC)</dt><dd>${esc(msg.received_at)}</dd>
    </dl>
    <h3>Text</h3>
    ${text ? `<pre>${esc(text)}</pre>` : '<p class="muted">No plain-text part.</p>'}
    ${msg.html_content ? `<h3>HTML <a class="small" href="/admin/message/html?id=${esc(msg.id)}" target="_blank" rel="noopener noreferrer">open alone</a></h3>
      <p class="muted">Shown in a sandbox: scripts, forms and links are disabled; remote images may load.</p>
      <iframe sandbox src="/admin/message/html?id=${esc(msg.id)}" title="Email HTML" referrerpolicy="no-referrer"></iframe>` : ''}
    <form method="post" action="/admin/message/delete" class="card danger">
      ${csrfField(session)}
      <input type="hidden" name="id" value="${esc(msg.id)}">
      <button type="submit">Delete message</button>
    </form>`);
}

function emailHtmlHeaders(): Record<string, string> {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': EMAIL_HTML_CSP,
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  };
}

async function messageHtml(env: AdminEnv, url: URL): Promise<Response> {
  const msg = await loadPrivateMessage(env, url.searchParams.get('id'));
  if (!msg || !msg.html_content) return new Response('Not found', { status: 404, headers: emailHtmlHeaders() });
  return new Response(String(msg.html_content), { status: 200, headers: emailHtmlHeaders() });
}

// ---------------------------------------------------------------- actions

async function deleteMessage(env: AdminEnv, form: FormData): Promise<Response> {
  const msg = await loadPrivateMessage(env, form.get('id'));
  if (!msg) return page('Not found', '<h1>Message not found</h1><p><a href="/admin">Back</a></p>', 404);
  await env.TEMP_MAIL_DB.prepare('DELETE FROM messages WHERE id = ?').bind(msg.id).run();
  return redirect('/admin/mailbox?id=' + encodeURIComponent(String(msg.mailbox_id)));
}

async function deleteMailbox(env: AdminEnv, form: FormData): Promise<Response> {
  const mb = await loadPrivateMailbox(env, form.get('id'));
  if (!mb) return page('Not found', '<h1>Mailbox not found</h1><p><a href="/admin">Back</a></p>', 404);
  if (form.get('confirm') !== 'yes') return page('Not deleted', `<h1>Not deleted</h1><p>Tick the confirmation box. <a href="/admin/mailbox?id=${esc(mb.id)}">Back</a></p>`, 400);
  const db = env.TEMP_MAIL_DB;
  await db.batch([
    db.prepare('DELETE FROM messages WHERE mailbox_id = ?').bind(mb.id),
    db.prepare('DELETE FROM user_mailboxes WHERE mailbox_id = ? OR user_id IN (SELECT id FROM users WHERE lower(trim(username)) = ?)').bind(mb.id, mb.address),
    db.prepare('DELETE FROM users WHERE lower(trim(username)) = ?').bind(mb.address),
    db.prepare('DELETE FROM mailboxes WHERE id = ?').bind(mb.id),
  ]);
  return redirect('/admin');
}

async function deleteUser(env: AdminEnv, form: FormData): Promise<Response> {
  const n = Number(form.get('id'));
  const user = Number.isInteger(n) && n > 0
    ? await env.TEMP_MAIL_DB.prepare('SELECT id, username FROM users WHERE id = ?').bind(n).first<any>()
    : null;
  if (!user || !isPrivateAddress(env, user.username)) {
    return page('Not found', '<h1>Login not found</h1><p><a href="/admin">Back</a></p>', 404);
  }
  const db = env.TEMP_MAIL_DB;
  await db.batch([
    db.prepare('DELETE FROM user_mailboxes WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
  ]);
  return redirect('/admin');
}

async function createPrivateLogin(env: AdminEnv, form: FormData): Promise<Response> {
  const parts = splitAddress(form.get('address'));
  const address = parts ? `${parts.local}@${parts.domain}` : '';
  const password = String(form.get('password') || '');
  if (!parts || !isPrivateAddress(env, address)) {
    return page('Not created', '<h1>Not created</h1><p>The address must be on a private domain. <a href="/admin">Back</a></p>', 400);
  }
  if (password.length < MIN_APP_PASSWORD_LENGTH || password.length > 1024) {
    return page('Not created', `<h1>Not created</h1><p>The password needs at least ${MIN_APP_PASSWORD_LENGTH} characters. <a href="/admin">Back</a></p>`, 400);
  }
  const db = env.TEMP_MAIL_DB;
  const mailboxId = await getOrCreateMailboxId(db, address);
  const hash = await hashPassword(password, USER_PBKDF2_ITERATIONS);
  // Delete + insert gives the login a new id, so tokens of an older login stop working.
  await db.batch([
    db.prepare('DELETE FROM user_mailboxes WHERE user_id IN (SELECT id FROM users WHERE lower(trim(username)) = ?)').bind(address),
    db.prepare('DELETE FROM users WHERE lower(trim(username)) = ?').bind(address),
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').bind(address, hash, PRIVATE_ROLE),
  ]);
  return redirect('/admin/mailbox?id=' + encodeURIComponent(String(mailboxId)));
}

// ---------------------------------------------------------------- HTML

export function esc(value: unknown): string {
  return String(value ?? '').replace(/[&<>"'`]/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;',
  }[c] as string));
}

function loginLabel(role: unknown): string {
  if (role === PRIVATE_ROLE) return 'admin-created';
  if (role) return '<span class="warn">blocked leftover</span>';
  return 'none';
}

function csrfField(session: Session): string {
  return `<input type="hidden" name="csrf" value="${esc(session.csrf)}">`;
}

function postButton(action: string, session: Session, fields: Record<string, unknown>, label: string, danger = false): string {
  const hidden = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join('');
  return `<form method="post" action="${esc(action)}" class="inline">${csrfField(session)}${hidden}<button type="submit"${danger ? ' class="danger"' : ''}>${esc(label)}</button></form>`;
}

function header(session: Session): string {
  return `<header><strong><a href="/admin">DuckMail admin</a></strong>
    <form method="post" action="/admin/logout" class="inline">${csrfField(session)}<button type="submit">Sign out</button></form></header>`;
}

function redirect(location: string, extra: Record<string, string> = {}): Response {
  return new Response(null, { status: 303, headers: { Location: location, 'Cache-Control': 'no-store', ...extra } });
}

function page(title: string, body: string, status = 200, extra: Record<string, string> = {}): Response {
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)}</title>
<style>
  :root { color-scheme: light dark; --fg:#1b1b1f; --bg:#fafafa; --muted:#5f6368; --line:#d7d7db; --accent:#0b57d0; --danger:#b3261e; --card:#fff; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e8e8ea; --bg:#151518; --muted:#a0a0a8; --line:#34343a; --accent:#8ab4f8; --danger:#f2b8b5; --card:#1e1e22; } }
  * { box-sizing: border-box; }
  body { margin:0; padding:16px; font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color:var(--fg); background:var(--bg); }
  main { max-width: 960px; margin: 0 auto; }
  a { color: var(--accent); }
  header { display:flex; justify-content:space-between; align-items:center; gap:12px; padding-bottom:8px; border-bottom:1px solid var(--line); margin-bottom:16px; }
  header a { color: inherit; text-decoration: none; }
  h1 { font-size: 1.5rem; } h2 { font-size: 1.2rem; margin-top: 28px; } h3 { font-size: 1rem; margin-top: 20px; }
  .muted { color: var(--muted); } .warn { color: var(--danger); } .small { font-size: .85rem; font-weight: normal; }
  .err { color: var(--danger); font-weight: 600; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin: 16px 0; }
  .card.danger { border-color: var(--danger); }
  label { display:block; margin: 8px 0 4px; }
  input[type=password], input[type=email], input[type=search] { width: 100%; max-width: 420px; padding: 8px; font: inherit; border:1px solid var(--line); border-radius:6px; background: var(--bg); color: var(--fg); }
  button { font: inherit; padding: 6px 14px; margin-top: 8px; border-radius: 6px; border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }
  button.danger, .danger button { border-color: var(--danger); color: var(--danger); }
  form.inline { display: inline; } form.inline button { margin-top: 0; }
  form.search input { display: inline-block; width: auto; min-width: 0; flex: 1 1 200px; }
  form.search { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; } form.search label { width: 100%; margin: 0; }
  form.search button { margin-top: 0; }
  .scroll { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: .95rem; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  .num { text-align: right; } .wrap { overflow-wrap: anywhere; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; } dt { color: var(--muted); } dd { margin: 0; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
  iframe { width: 100%; height: 480px; border: 1px solid var(--line); border-radius: 8px; background: #fff; }
</style></head>
<body><main>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': PAGE_CSP,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      // Not "no-referrer": with it, browsers send "Origin: null" on form posts
      // and the Origin check below would refuse every admin form.
      'Referrer-Policy': 'same-origin',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow',
      ...extra,
    },
  });
}
