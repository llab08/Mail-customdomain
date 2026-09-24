// Failed /token logins are limited per IP (D1 table auth_failures).
import { reset } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import { E, call, createAccount, getToken, query } from './helpers';
import { CLIENT_IP_HEADER, CLIENT_IP_SIGNATURE_HEADER, nowSeconds, signClientIp } from '../security';

/** The DuckMail web app's proxy: every call comes from PROXY_IP, the browser's IP is in a signed header. */
const PROXY_IP = '203.0.113.200';
async function tokenViaProxy(address: string, password: string, browserIp: string | null, opts: { signature?: string; env?: any } = {}) {
  const headers: Record<string, string> = {};
  if (browserIp) {
    headers[CLIENT_IP_HEADER] = browserIp;
    headers[CLIENT_IP_SIGNATURE_HEADER] = opts.signature ?? await signClientIp(E.CLIENT_IP_SECRET, browserIp, nowSeconds());
  }
  return call('POST', '/token', { body: { address, password }, ip: PROXY_IP, headers, env: opts.env });
}

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

  it('counts parallel failures atomically (no check-then-record race)', async () => {
    await createAccount('par@public.test', 'right-password');
    const res = await Promise.all(Array.from({ length: 30 }, (_, i) => getToken('par@public.test', 'wrong-' + i, '198.51.100.40')));
    const passed = res.filter(r => r.status !== 429).length;
    expect(passed).toBeLessThanOrEqual(10);
    expect(res.every(r => r.status === 401 || r.status === 429)).toBe(true);
    // Refused attempts are refunded: the counter holds the 10 real failures.
    expect((await getToken('par@public.test', 'right-password', '198.51.100.40')).status).toBe(429);
    expect((await getToken('par@public.test', 'right-password', '198.51.100.41')).status).toBe(200);
  });

  it('successful logins are not counted as failures', async () => {
    await createAccount('ok@public.test', 'right-password');
    // Attempts count while in flight, so up to the limit may run in parallel...
    const res = await Promise.all(Array.from({ length: 10 }, () => getToken('ok@public.test', 'right-password', '198.51.100.42')));
    expect(res.map(r => r.status)).toEqual(Array(10).fill(200));
    // ...and once settled, successes leave nothing behind.
    for (let i = 0; i < 30; i++) expect((await getToken('ok@public.test', 'right-password', '198.51.100.42')).status).toBe(200);
    const rows = await query('SELECT count FROM auth_failures');
    expect(rows.every(r => Number(r.count) === 0)).toBe(true);
  });

  it('counts IPv6 clients per /64', async () => {
    await createAccount('six@public.test', 'right-password');
    for (let i = 1; i <= 10; i++) {
      expect((await getToken('six@public.test', 'wrong', `2001:db8:5:6::${i.toString(16)}`)).status).toBe(401);
    }
    expect((await getToken('six@public.test', 'right-password', '2001:db8:5:6::ff')).status).toBe(429);
    expect((await getToken('six@public.test', 'right-password', '2001:db8:5:7::1')).status).toBe(200);
  });
});

describe('/token behind the DuckMail web-app proxy (signed client IP)', () => {
  it('one user\'s failures through the proxy do not block other users of the proxy', async () => {
    await createAccount('victim@public.test', 'victim-password');
    await createAccount('grace@public.test', 'grace-password');
    // An attacker behind the proxy: 100 junk failures, then 10 wrong guesses for victim@.
    for (let i = 0; i < 100; i++) await tokenViaProxy(`nobody${i}@public.test`, 'x', '198.51.100.66');
    for (let i = 0; i < 10; i++) await tokenViaProxy('victim@public.test', 'guess-' + i, '198.51.100.66');
    expect((await tokenViaProxy('victim@public.test', 'victim-password', '198.51.100.66')).status).toBe(429);
    // Everyone else using the same proxy is unaffected, the victim included.
    expect((await tokenViaProxy('victim@public.test', 'victim-password', '198.51.100.77')).status).toBe(200);
    expect((await tokenViaProxy('grace@public.test', 'grace-password', '2001:db8:9::1')).status).toBe(200);
  });

  it('ignores an unsigned, forged or stale client IP and counts the connecting IP', async () => {
    await createAccount('mallory@public.test', 'right-password');
    const stale = await signClientIp(E.CLIENT_IP_SECRET, '198.51.100.1', nowSeconds() - 3600);
    for (let i = 0; i < 10; i++) {
      // A different claimed IP each time does not buy fresh attempts.
      const claimed = `198.51.100.${i + 1}`;
      const signature = i % 3 === 0 ? 'v1.1.AAAA' : i % 3 === 1 ? stale : 'nonsense';
      expect((await tokenViaProxy('mallory@public.test', 'wrong', claimed, { signature })).status).toBe(401);
    }
    expect((await tokenViaProxy('mallory@public.test', 'right-password', null)).status).toBe(429);
  });

  it('without CLIENT_IP_SECRET the Worker ignores the header', async () => {
    await createAccount('nosecret@public.test', 'right-password');
    const env = { ...E, CLIENT_IP_SECRET: undefined };
    for (let i = 0; i < 10; i++) await tokenViaProxy('nosecret@public.test', 'wrong', `198.51.100.${i + 1}`, { env });
    expect((await tokenViaProxy('nosecret@public.test', 'right-password', '198.51.100.99', { env })).status).toBe(429);
  });
});
