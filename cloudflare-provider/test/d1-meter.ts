// Measures D1 rows read/written per request against the local D1 (the same
// SQLite engine and counters as production D1): wraps the TEMP_MAIL_DB
// binding and records meta.rows_read / meta.rows_written of every statement.
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../worker';
import { ensureSchema, forgetSchemaCheck, initDatabase } from '../database.js';
import { ensureAuthFailuresTable, hashPassword } from '../security';
import { E, ORIGIN, call, cookieFrom, json } from './helpers';

export interface Stmt {
  sql: string;
  binds: unknown[];
  rows_read: number;
  rows_written: number;
}

const REAL = Symbol('real statement');
const SQL = Symbol('statement sql');

function short(sql: string): string {
  return sql.replace(/\s+/g, ' ').trim();
}

/** A D1Database look-alike that forwards to `db` and records every statement's meta. */
export function meteredDb(db: D1Database, log: Stmt[]): D1Database {
  const record = (sql: string, binds: unknown[], meta: any) => {
    log.push({ sql: short(sql), binds, rows_read: Number(meta?.rows_read || 0), rows_written: Number(meta?.rows_written || 0) });
  };
  const wrap = (stmt: D1PreparedStatement, sql: string, binds: unknown[] = []): D1PreparedStatement => ({
    [REAL]: stmt,
    [SQL]: [sql, binds],
    bind: (...args: unknown[]) => wrap(stmt.bind(...args), sql, args),
    async all() { const r = await stmt.all(); record(sql, binds, r.meta); return r; },
    async run() { const r = await stmt.run(); record(sql, binds, r.meta); return r; },
    // D1's first() runs the whole statement and returns its first row, so
    // all() reads exactly the same rows.
    async first(col?: string) {
      const r = await stmt.all();
      record(sql, binds, r.meta);
      const row: any = r.results?.[0];
      if (!row) return null;
      return col === undefined ? row : (row[col] ?? null);
    },
  }) as unknown as D1PreparedStatement;
  return {
    prepare: (sql: string) => wrap(db.prepare(sql), sql),
    async batch(stmts: any[]) {
      const res = await db.batch(stmts.map(s => s[REAL] ?? s));
      res.forEach((r: any, i: number) => {
        const [sql, binds] = stmts[i][SQL] ?? ['(unmetered statement)', []];
        record(sql, binds, r.meta);
      });
      return res;
    },
    // exec() results carry no rows_read; run the (single) statement instead.
    async exec(sql: string) {
      const r = await db.prepare(sql).run();
      record(sql, [], r.meta);
      return { count: 1, duration: Number(r.meta?.duration || 0) };
    },
  } as unknown as D1Database;
}

export function totals(log: Stmt[]) {
  return {
    queries: log.length,
    rows_read: log.reduce((a, s) => a + s.rows_read, 0),
    rows_written: log.reduce((a, s) => a + s.rows_written, 0),
  };
}

// ---------------------------------------------------------------- seeding

export const SEED = {
  publicMailboxes: 4800,
  privateMailboxes: 200,
  orphanUsers: 190,
  messages: 7500,
  aliceMessages: 20,
  hotPrivateMessages: 300,
  authFailures: 500,
};

export const ALICE = 'alice@public.test';
export const ALICE_PASSWORD = 'alice-password-1';

async function exec(sql: string, ...binds: unknown[]) {
  await E.TEMP_MAIL_DB.prepare(sql).bind(...binds).run();
}

/**
 * Seeds production-like volumes: 5,000 mailboxes (4,800 public, 200 on the
 * private domain incl. subdomains), 5,000 users, 7,500 messages, 500
 * auth_failures rows (half expired). alice@public.test has a real login
 * and 20 messages; hello@private.test is a busy private catch-all.
 */
export async function seedProductionLike() {
  await initDatabase(E.TEMP_MAIL_DB);
  await ensureAuthFailuresTable(E.TEMP_MAIL_DB);
  const alicePw = await hashPassword(ALICE_PASSWORD);
  await exec(`WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < ?)
    INSERT INTO mailboxes (address, local_part, domain, last_accessed_at)
    SELECT 'user' || n || '@public.test', 'user' || n, 'public.test', CURRENT_TIMESTAMP FROM s`, SEED.publicMailboxes - 1);
  await exec(`INSERT INTO mailboxes (address, local_part, domain, last_accessed_at) VALUES (?, 'alice', 'public.test', CURRENT_TIMESTAMP)`, ALICE);
  // Private: hello@ (forwarded, busy), 5 admin-created logins, 5 blocked
  // leftovers, 2 on subdomains, the rest catch-all spam.
  const priv = ['hello@private.test', 'x@sub.private.test', 'y@mail.private.test'];
  for (let i = 0; i < 5; i++) priv.push(`team${i}@private.test`, `leak${i}@private.test`);
  await E.TEMP_MAIL_DB.batch(priv.map(a => E.TEMP_MAIL_DB.prepare(
    'INSERT INTO mailboxes (address, local_part, domain) VALUES (?, ?, ?)').bind(a, a.split('@')[0], a.split('@')[1])));
  await exec(`WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < ?)
    INSERT INTO mailboxes (address, local_part, domain)
    SELECT 'spam' || n || '@private.test', 'spam' || n, 'private.test' FROM s`, SEED.privateMailboxes - priv.length);

  // Users: every public mailbox has a login (alice's is real), 190 old logins
  // without a mailbox, 10 on the private domain.
  await exec(`INSERT INTO users (username, password_hash, role)
    SELECT address, 'pbkdf2-sha256$20000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'user'
      FROM mailboxes WHERE domain = 'public.test' AND address <> ? ORDER BY id`, ALICE);
  await exec('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ALICE, alicePw, 'user');
  await exec(`WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < ?)
    INSERT INTO users (username, password_hash, role) SELECT 'Orphan' || n || '@Public.test', 'x', 'user' FROM s`, SEED.orphanUsers);
  for (let i = 0; i < 5; i++) {
    await exec('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', `team${i}@private.test`, 'x', 'private');
    await exec('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', `leak${i}@private.test`, 'x', 'user');
  }

  // Messages: 20 for alice, 300 for hello@private.test, 1,200 over the other
  // private mailboxes, the rest over the public mailboxes.
  const aliceId = (await E.TEMP_MAIL_DB.prepare('SELECT id FROM mailboxes WHERE address = ?').bind(ALICE).first()).id;
  const helloId = (await E.TEMP_MAIL_DB.prepare('SELECT id FROM mailboxes WHERE address = ?').bind('hello@private.test').first()).id;
  const insertMessages = (count: number, mailboxSql: string, ...binds: unknown[]) => exec(
    `WITH RECURSIVE s(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM s WHERE n < ? - 1),
          box AS (SELECT id, row_number() OVER (ORDER BY id) - 1 AS rn, count(*) OVER () AS total FROM mailboxes WHERE ${mailboxSql})
     INSERT INTO messages (mailbox_id, sender, subject, content, html_content, received_at)
     SELECT box.id, 'sender' || s.n || '@example.com', 'Subject ' || s.n, 'Body of message ' || s.n, NULL,
            datetime('2026-09-24 12:00:00', '-' || s.n || ' minutes')
       FROM s JOIN box ON box.rn = s.n % box.total`, count, ...binds);
  await insertMessages(SEED.aliceMessages, 'id = ?', aliceId);
  await insertMessages(SEED.hotPrivateMessages, 'id = ?', helloId);
  const otherPrivate = 1200;
  await insertMessages(otherPrivate, "domain LIKE '%private.test' AND id <> ?", helloId);
  await insertMessages(SEED.messages - SEED.aliceMessages - SEED.hotPrivateMessages - otherPrivate,
    "domain = 'public.test' AND id <> ?", aliceId);

  // Rate-limit rows of the current 15-minute window.
  await seedAuthFailures(SEED.authFailures, 60);
}

/** Adds `count` auth_failures rows whose window started `ageSeconds` ago. */
export async function seedAuthFailures(count: number, ageSeconds: number) {
  await exec(`WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < ?)
    INSERT INTO auth_failures (key, count, window_start)
    SELECT lower(hex(randomblob(32))), 1 + n % 5, ? FROM s`, count, Math.floor(Date.now() / 1000) - ageSeconds);
}

export async function tableCounts() {
  const out: Record<string, number> = {};
  for (const t of ['mailboxes', 'users', 'messages', 'auth_failures']) {
    out[t] = Number((await E.TEMP_MAIL_DB.prepare(`SELECT COUNT(*) AS c FROM ${t}`).first()).c);
  }
  return out;
}

// ---------------------------------------------------------------- scenarios

export interface Measurement {
  name: string;
  status: number | string;
  log: Stmt[];
}

/** Runs one request (or email delivery) with a metered binding. */
export async function measure(name: string, fn: (env: any) => Promise<Response | void>): Promise<Measurement> {
  const log: Stmt[] = [];
  const env = { ...E, TEMP_MAIL_DB: meteredDb(E.TEMP_MAIL_DB, log) };
  const res = await fn(env);
  return { name, status: res ? res.status : '-', log };
}

export async function deliverWith(env: any, to: string, subject = 'Metered mail') {
  const raw = [`From: sender@example.com`, `To: ${to}`, `Subject: ${subject}`, 'Content-Type: text/plain; charset=utf-8', '', 'body text', ''].join('\r\n');
  const message = { from: 'sender@example.com', to, raw, headers: new Headers({ subject }), rawSize: raw.length, forward: async () => {} };
  const ctx = createExecutionContext();
  await (worker as any).email(message, env, ctx);
  await waitOnExecutionContext(ctx);
}

/** Every endpoint of the measurement table, in order, on a seeded database. */
export async function runScenarios(): Promise<Measurement[]> {
  const out: Measurement[] = [];
  // The one-time check a fresh isolate makes before its first D1 request;
  // every row below is measured after it (warm isolate).
  forgetSchemaCheck();
  out.push(await measure('schema check (first D1 request of an isolate)', env => ensureSchema(env.TEMP_MAIL_DB)));
  out.push(await measure('GET /domains', env => call('GET', '/domains', { env })));
  out.push(await measure('POST /accounts (new address)', env =>
    call('POST', '/accounts', { env, body: { address: 'newcomer@public.test', password: 'pw-newcomer' } })));
  out.push(await measure('POST /token (ok)', env =>
    call('POST', '/token', { env, body: { address: ALICE, password: ALICE_PASSWORD }, ip: '198.51.100.10' })));
  out.push(await measure('POST /token (wrong password)', env =>
    call('POST', '/token', { env, body: { address: ALICE, password: 'wrong' }, ip: '198.51.100.11' })));
  const token = (await json(await call('POST', '/token', { body: { address: ALICE, password: ALICE_PASSWORD }, ip: '198.51.100.12' }))).token;
  out.push(await measure('GET /me', env => call('GET', '/me', { env, token })));
  out.push(await measure('GET /messages', env => call('GET', '/messages', { env, token })));
  const firstId = (await json(await call('GET', '/messages', { token })))['hydra:member'][0].id;
  out.push(await measure('GET /messages/:id', env => call('GET', `/messages/${firstId}`, { env, token })));
  out.push(await measure('email() to an existing mailbox', env => deliverWith(env, ALICE)));
  out.push(await measure('email() to a new address', env => deliverWith(env, 'brand-new@private.test')));
  let cookie = '';
  out.push(await measure('POST /admin/login', async env => {
    const res = await call('POST', '/admin/login', { env, form: { password: E.TEST_ADMIN_PASSWORD }, origin: ORIGIN, ip: '192.0.2.99' });
    cookie = cookieFrom(res);
    return res;
  }));
  out.push(await measure('GET /admin (dashboard)', env => call('GET', '/admin', { env, cookie })));
  out.push(await measure('GET /admin?page=2', env => call('GET', '/admin?page=2', { env, cookie })));
  out.push(await measure('GET /admin?q=spam1', env => call('GET', '/admin?q=spam1', { env, cookie })));
  const helloId = (await E.TEMP_MAIL_DB.prepare('SELECT id FROM mailboxes WHERE address = ?').bind('hello@private.test').first()).id;
  out.push(await measure('GET /admin/mailbox (300 msgs)', env => call('GET', `/admin/mailbox?id=${helloId}`, { env, cookie })));
  // After a burst of failed logins 15+ minutes ago: 250 expired rows wait for cleanup.
  await seedAuthFailures(250, 2000);
  out.push(await measure('POST /token (wrong password), 250 expired rows pending', env =>
    call('POST', '/token', { env, body: { address: ALICE, password: 'wrong' }, ip: '198.51.100.13' })));
  return out;
}

export function formatReport(title: string, rows: Measurement[], detail = true): string {
  const lines = [`### ${title}`, '', '| Request | HTTP | Statements | rows_read | rows_written |', '|---|---|---:|---:|---:|'];
  for (const r of rows) {
    const t = totals(r.log);
    lines.push(`| ${r.name} | ${r.status} | ${t.queries} | ${t.rows_read.toLocaleString('en-US')} | ${t.rows_written.toLocaleString('en-US')} |`);
  }
  if (detail) {
    lines.push('');
    for (const r of rows) {
      lines.push(`#### ${r.name}`);
      for (const s of r.log) lines.push(`  ${String(s.rows_read).padStart(6)} r ${String(s.rows_written).padStart(4)} w  ${s.sql.slice(0, 150)}`);
    }
  }
  return lines.join('\n');
}
