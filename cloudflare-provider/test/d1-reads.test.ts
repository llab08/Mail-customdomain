// D1 rows read per request. The D1 free plan allows 5,000,000 rows read per
// day; on 25 Sep 2026 the Worker used them up because every request re-ran
// the schema setup (a COUNT over all of messages, ~7,500 rows) and each admin
// dashboard view read ~2,000,000 rows. These tests seed production-like
// volumes into the local D1 (same SQLite engine and counters as production)
// and hold the hot paths to a row budget.
//
// Print the full table with every statement:
//   D1_READS_REPORT=1 npx vitest run test/d1-reads.test.ts --reporter=verbose
import { reset } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import { E, call, createAccount, deliver, getToken, json, query, tokenFor } from './helpers';
import {
  ALICE, ALICE_PASSWORD, Measurement, SEED, deliverWith, formatReport, measure, meteredDb, runScenarios, seedAuthFailures,
  seedProductionLike, totals,
} from './d1-meter';
import { SCHEMA_MARKER, ensureSchema, forgetSchemaCheck, initDatabase } from '../database.js';
import { EXPIRED_ROWS_PER_CLEANUP } from '../security';

beforeEach(async () => {
  await reset();
});

/**
 * Rows read allowed per request on the seeded database (5,000 mailboxes,
 * 5,000 users, 7,500 messages, 500 live auth_failures rows; alice has 20
 * messages). Before the fix every one of these read 7,500+ rows.
 */
const BUDGET: Record<string, number> = {
  'schema check (first D1 request of an isolate)': 50,
  'GET /domains': 0,
  'POST /accounts (new address)': 20,
  'POST /token (ok)': 30,
  'POST /token (wrong password)': 30,
  'GET /me': 5,
  'GET /messages': SEED.aliceMessages + 20,
  'GET /messages/:id': 10,
  'email() to an existing mailbox': 15,
  'email() to a new address': 15,
  'POST /admin/login': 30,
  // One pass over mailbox addresses and one over usernames (the private
  // filter is a suffix match), a few index rows per private mailbox and the
  // messages of the shown page. Before: ~1,950,000.
  'GET /admin (dashboard)': 20_000,
  'GET /admin?page=2': 20_000,
  'GET /admin?q=spam1': 20_000,
  // COUNT over this mailbox + one page. Before: 8,421.
  'GET /admin/mailbox (300 msgs)': SEED.hotPrivateMessages + 100,
  // The cleanup deletes at most EXPIRED_ROWS_PER_CLEANUP rows (4 rows read each).
  'POST /token (wrong password), 250 expired rows pending': 30 + 4 * EXPIRED_ROWS_PER_CLEANUP,
};

const HOT_PATHS = [
  'POST /accounts (new address)', 'POST /token (ok)', 'POST /token (wrong password)', 'GET /me', 'GET /messages',
  'GET /messages/:id', 'email() to an existing mailbox', 'email() to a new address', 'POST /admin/login',
];

async function plan(sql: string, binds: unknown[]): Promise<string[]> {
  const res = await E.TEMP_MAIL_DB.prepare('EXPLAIN QUERY PLAN ' + sql).bind(...binds).all();
  return (res.results || []).map((r: any) => String(r.detail));
}

describe('D1 rows read per request (production-like volumes)', () => {
  it('keeps every request within its row budget, and the hot paths on indexes', async () => {
    await seedProductionLike();
    const rows = await runScenarios();
    if (E.D1_READS_REPORT) console.log('\n' + formatReport('D1 rows per request', rows) + '\n');

    expect(rows.map(r => r.name)).toEqual(Object.keys(BUDGET));
    for (const r of rows) {
      expect(totals(r.log).rows_read, r.name).toBeLessThanOrEqual(BUDGET[r.name]);
      expect(r.status, r.name).not.toBe(500);
    }

    const byName = new Map<string, Measurement>(rows.map(r => [r.name, r]));
    for (const name of HOT_PATHS) {
      for (const s of byName.get(name)!.log) {
        // Schema work happens once per isolate, never on a request.
        expect(s.sql, name).not.toMatch(/sqlite_master|^CREATE |^PRAGMA |^ALTER |^DROP /i);
        // No full table scan (EXPLAIN QUERY PLAN "SCAN <table>").
        for (const step of await plan(s.sql, s.binds)) {
          expect(step, `${name}: ${s.sql}`).not.toMatch(/^SCAN /);
        }
      }
    }
  }, 120_000);

  it('checks the schema once per isolate: later requests make no schema queries', async () => {
    await createAccount(ALICE, ALICE_PASSWORD);
    const token = await tokenFor(ALICE, ALICE_PASSWORD);
    forgetSchemaCheck();
    const first = await measure('first', env => call('GET', '/me', { env, token }));
    const second = await measure('second', env => call('GET', '/me', { env, token }));
    const mail = await measure('mail', env => deliverWith(env, ALICE));
    expect(first.log.filter(s => /sqlite_master/.test(s.sql))).toHaveLength(1);
    for (const m of [second, mail]) expect(m.log.some(s => /sqlite_master|^CREATE |^PRAGMA /i.test(s.sql)), m.name).toBe(false);
    // The Worker never counts all messages any more.
    for (const m of [first, second, mail]) expect(m.log.some(s => /COUNT\(1\) as c FROM messages/i.test(s.sql))).toBe(false);
  });

  it('runs the full migration when the schema marker is missing, and not again once it exists', async () => {
    forgetSchemaCheck();
    const log: any[] = [];
    await ensureSchema(meteredDb(E.TEMP_MAIL_DB, log));
    expect(log.some(s => /CREATE TABLE IF NOT EXISTS messages/.test(s.sql))).toBe(true);
    expect(log[log.length - 1].sql).toContain(SCHEMA_MARKER);
    const names = (await query("SELECT name FROM sqlite_master WHERE type = 'index'")).map(r => r.name);
    expect(names).toEqual(expect.arrayContaining(['idx_messages_mailbox_received', SCHEMA_MARKER, 'idx_users_username_norm']));
    expect(names).not.toContain('idx_messages_mailbox_id');

    forgetSchemaCheck();
    const again: any[] = [];
    await ensureSchema(meteredDb(E.TEMP_MAIL_DB, again));
    expect(again.map(s => s.sql)).toEqual([expect.stringContaining('sqlite_master')]);
  });
});

describe('auth_failures cleanup', () => {
  it('restarts an expired window even when the bounded cleanup has not reached it yet', async () => {
    await createAccount('frank@public.test', 'right-password');
    for (let i = 0; i < 10; i++) expect((await getToken('frank@public.test', 'wrong-' + i, '198.51.100.1')).status).toBe(401);
    expect((await getToken('frank@public.test', 'right-password', '198.51.100.1')).status).toBe(429);
    // Expire frank's window, behind many older expired rows the cleanup deletes first.
    await E.TEMP_MAIL_DB.prepare('UPDATE auth_failures SET window_start = window_start - 901').run();
    await seedAuthFailures(3 * EXPIRED_ROWS_PER_CLEANUP, 5000);
    expect((await getToken('frank@public.test', 'right-password', '198.51.100.1')).status).toBe(200);
    // A fresh window starts counting from zero again.
    for (let i = 0; i < 10; i++) expect((await getToken('frank@public.test', 'wrong-' + i, '198.51.100.1')).status).toBe(401);
    expect((await getToken('frank@public.test', 'right-password', '198.51.100.1')).status).toBe(429);
  });

  it('deletes at most EXPIRED_ROWS_PER_CLEANUP expired rows per attempt and keeps live ones', async () => {
    await initDatabase(E.TEMP_MAIL_DB);
    await seedAuthFailures(120, 5000);
    await seedAuthFailures(30, 60);
    const count = async () => Number((await query('SELECT COUNT(*) AS c FROM auth_failures WHERE window_start <= ?', Math.floor(Date.now() / 1000) - 900))[0].c);
    expect(await count()).toBe(120);
    await getToken('nobody@public.test', 'x', '198.51.100.2');
    expect(await count()).toBe(120 - EXPIRED_ROWS_PER_CLEANUP);
    await getToken('nobody@public.test', 'x', '198.51.100.2');
    await getToken('nobody@public.test', 'x', '198.51.100.2');
    expect(await count()).toBe(0);
    // 30 seeded live rows + this client's two counters.
    expect((await query('SELECT COUNT(*) AS c FROM auth_failures'))[0].c).toBe(32);
  });
});

describe('GET /messages totals', () => {
  it('reports the same hydra:totalItems on every page, counting only when a page is full', async () => {
    await createAccount('many@public.test', 'pw');
    const token = await tokenFor('many@public.test', 'pw');
    const page = (p: string) => call('GET', '/messages' + p, { token }).then(json);
    expect((await page(''))['hydra:totalItems']).toBe(0);
    for (let i = 0; i < 35; i++) await deliver({ to: 'many@public.test', subject: 'm' + i });
    const p1 = await page('');
    const p2 = await page('?page=2');
    const p3 = await page('?page=3');
    expect([p1, p2, p3].map(p => p['hydra:totalItems'])).toEqual([35, 35, 35]);
    expect([p1, p2, p3].map(p => p['hydra:member'].length)).toEqual([30, 5, 0]);
    // Newest first; mail from the same second newest id first.
    const subjects = [...p1['hydra:member'], ...p2['hydra:member']].map((m: any) => m.subject);
    expect(subjects).toEqual(Array.from({ length: 35 }, (_, i) => 'm' + (34 - i)));
  });
});

describe('legacy "emails" table', () => {
  async function createLegacyTable() {
    await E.TEMP_MAIL_DB.prepare('CREATE TABLE emails (id INTEGER PRIMARY KEY, mailbox TEXT, sender TEXT, subject TEXT, content TEXT, html_content TEXT, received_at TEXT, is_read INTEGER)').run();
    await E.TEMP_MAIL_DB.prepare("INSERT INTO emails (mailbox, sender, subject, content, received_at, is_read) VALUES ('old@public.test', 'a@example.com', 'from the old table', 'hi', '2024-01-01 00:00:00', 1)").run();
  }

  it('is migrated into an empty messages table', async () => {
    await createLegacyTable();
    await initDatabase(E.TEMP_MAIL_DB);
    const rows = await query('SELECT m.address, x.subject, x.is_read FROM messages x JOIN mailboxes m ON m.id = x.mailbox_id');
    expect(rows).toEqual([{ address: 'old@public.test', subject: 'from the old table', is_read: 1 }]);
    await initDatabase(E.TEMP_MAIL_DB);
    expect(await query('SELECT id FROM messages')).toHaveLength(1);
  });

  it('is left alone when messages already has mail', async () => {
    await initDatabase(E.TEMP_MAIL_DB);
    await deliver({ to: 'new@public.test' });
    await createLegacyTable();
    await initDatabase(E.TEMP_MAIL_DB);
    expect(await query('SELECT id FROM messages')).toHaveLength(1);
  });
});
