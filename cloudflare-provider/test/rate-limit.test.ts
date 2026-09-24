// Failed /token logins are limited per IP (D1 table auth_failures).
import { reset } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import { E, createAccount, getToken, query } from './helpers';

beforeEach(async () => {
  await reset();
});

async function expireWindows() {
  await E.TEMP_MAIL_DB.prepare('UPDATE auth_failures SET window_start = window_start - 901').run();
}

describe('/token failure limits', () => {
  it('blocks an address from one IP after 10 failures, even with the right password', async () => {
    await createAccount('frank@public.test', 'right-password');
    for (let i = 0; i < 10; i++) {
      expect((await getToken('frank@public.test', 'wrong-' + i, '198.51.100.1')).status).toBe(401);
    }
    const blocked = await getToken('frank@public.test', 'right-password', '198.51.100.1');
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get('Retry-After'))).toBeGreaterThan(0);

    // Another IP is not affected (the DuckMail web app proxies many users).
    expect((await getToken('frank@public.test', 'right-password', '198.51.100.2')).status).toBe(200);

    // The window expires.
    await expireWindows();
    expect((await getToken('frank@public.test', 'right-password', '198.51.100.1')).status).toBe(200);
  });

  it('blocks one IP after 100 failures across many addresses', async () => {
    await createAccount('grace@public.test', 'right-password');
    for (let i = 0; i < 100; i++) {
      expect((await getToken(`nobody${i}@public.test`, 'x', '198.51.100.3')).status).toBe(401);
    }
    expect((await getToken('grace@public.test', 'right-password', '198.51.100.3')).status).toBe(429);
    expect((await getToken('grace@public.test', 'right-password', '198.51.100.4')).status).toBe(200);
  });

  it('a successful login clears the per-address counter', async () => {
    await createAccount('heidi@public.test', 'right-password');
    for (let i = 0; i < 9; i++) await getToken('heidi@public.test', 'wrong', '198.51.100.5');
    expect((await getToken('heidi@public.test', 'right-password', '198.51.100.5')).status).toBe(200);
    for (let i = 0; i < 9; i++) await getToken('heidi@public.test', 'wrong', '198.51.100.5');
    expect((await getToken('heidi@public.test', 'right-password', '198.51.100.5')).status).toBe(200);
  });

  it('stores only hashed keys, never raw IPs or addresses', async () => {
    await getToken('ivan@public.test', 'wrong', '198.51.100.6');
    const rows = await query('SELECT key FROM auth_failures');
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      expect(r.key).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
