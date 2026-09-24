// Admin portal: login, session cookie, CSRF/Origin checks, mailbox pages,
// deletes, sandboxed email HTML and escaping.
import { reset } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD, E, ORIGIN, adminLogin, call, cookieFrom, csrfFrom, deliver, query, seedLegacyUser,
} from './helpers';

beforeEach(async () => {
  await reset();
});

const login = (password: string, opts: { origin?: string | null; ip?: string } = {}) =>
  call('POST', '/admin/login', { form: { password }, origin: opts.origin === undefined ? ORIGIN : opts.origin, ip: opts.ip });

function expectSafePageHeaders(res: Response) {
  const csp = res.headers.get('Content-Security-Policy') || '';
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).not.toContain('script-src');
  expect(res.headers.get('X-Frame-Options')).toBe('DENY');
  // "no-referrer" would make browsers send "Origin: null" on form posts, which the Origin check refuses.
  expect(res.headers.get('Referrer-Policy')).toBe('same-origin');
  expect(res.headers.get('Cache-Control')).toBe('no-store');
  expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
}

describe('admin login', () => {
  it('shows the login page without a session', async () => {
    const res = await call('GET', '/admin');
    expect(res.status).toBe(200);
    expectSafePageHeaders(res);
    const html = await res.text();
    expect(html).toContain('<form method="post" action="/admin/login"');
    expect(html).toContain('type="password"');
    expect(html).not.toMatch(/<script/i);
  });

  it('refuses a wrong password', async () => {
    const res = await login('not-the-password');
    expect(res.status).toBe(401);
    expect(res.headers.get('Set-Cookie')).toBeNull();
    expect(await res.text()).toContain('Wrong password');
  });

  it('sets a hardened 12 h session cookie on success', async () => {
    const res = await login(ADMIN_PASSWORD);
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('/admin');
    const set = res.headers.get('Set-Cookie') || '';
    expect(set).toMatch(/^duckmail_admin=[^;]+\.[^;]+;/);
    for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/admin', 'Max-Age=43200']) {
      expect(set).toContain(flag);
    }
    const dash = await call('GET', '/admin', { cookie: cookieFrom(res) });
    expect(await dash.text()).toContain('Private mailboxes');
  });

  it('refuses login posts without the same Origin', async () => {
    expect((await login(ADMIN_PASSWORD, { origin: null })).status).toBe(403);
    expect((await login(ADMIN_PASSWORD, { origin: 'https://evil.test' })).status).toBe(403);
  });

  it('locks an IP out after 10 failures', async () => {
    for (let i = 0; i < 10; i++) expect((await login('wrong-' + i, { ip: '192.0.2.7' })).status).toBe(401);
    const locked = await login(ADMIN_PASSWORD, { ip: '192.0.2.7' });
    expect(locked.status).toBe(429);
    expect(locked.headers.get('Set-Cookie')).toBeNull();
    expect(Number(locked.headers.get('Retry-After'))).toBeGreaterThan(0);
    expect((await login(ADMIN_PASSWORD, { ip: '192.0.2.8' })).status).toBe(303);
  });

  it('ignores forged, tampered or stale cookies', async () => {
    const cookie = await adminLogin();
    const [name, value] = cookie.split('=');
    const [body, sig] = value.split('.');
    const tampered = `${name}=${body}x.${sig}`;
    const forged = `${name}=${body}.${sig.slice(0, -2)}AA`;
    for (const c of [tampered, forged, 'duckmail_admin=abc', 'other=1']) {
      const html = await (await call('GET', '/admin', { cookie: c })).text();
      expect(html).toContain('action="/admin/login"');
    }
    // A new admin password invalidates existing sessions.
    const env = { ...E, ADMIN_PASSWORD_HASH: E.ADMIN_PASSWORD_HASH.replace(/\$[^$]+$/, '$AAAAAAAAAAAAAAAAAAAAAA==') };
    const html = await (await call('GET', '/admin', { cookie, env })).text();
    expect(html).toContain('action="/admin/login"');
  });

  it('logs out by clearing the cookie', async () => {
    const cookie = await adminLogin();
    const csrf = await csrfFrom(cookie);
    const res = await call('POST', '/admin/logout', { cookie, origin: ORIGIN, form: { csrf } });
    expect(res.status).toBe(303);
    const set = res.headers.get('Set-Cookie') || '';
    expect(set).toMatch(/^duckmail_admin=;/);
    expect(set).toContain('Max-Age=0');
    expect(set).toContain('Path=/admin');
  });

  it('is disabled until both admin secrets are set', async () => {
    const env = { ...E, ADMIN_PASSWORD_HASH: undefined };
    expect((await call('GET', '/admin', { env })).status).toBe(503);
    expect((await call('POST', '/admin/login', { env, origin: ORIGIN, form: { password: ADMIN_PASSWORD } })).status).toBe(503);
    const env2 = { ...E, ADMIN_SESSION_SECRET: 'short' };
    expect((await call('GET', '/admin', { env: env2 })).status).toBe(503);
  });

  it('redirects protected pages to the login page without a session', async () => {
    const res = await call('GET', '/admin/mailbox?id=1');
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('/admin');
    const post = await call('POST', '/admin/message/delete', { origin: ORIGIN, form: { id: '1', csrf: 'x' } });
    expect(post.status).toBe(401);
  });
});

describe('admin pages', () => {
  async function setup() {
    await deliver({ to: 'hello@private.test', from: 'client@example.com', subject: 'Quote request', text: 'Please send a quote.' });
    await deliver({ to: 'hello@private.test', from: 'bank@example.com', subject: 'Statement' });
    await deliver({ to: 'someone@public.test', subject: 'public mail' });
    const cookie = await adminLogin();
    const csrf = await csrfFrom(cookie);
    const box = (await query('SELECT id FROM mailboxes WHERE address = ?', 'hello@private.test'))[0];
    const pubBox = (await query('SELECT id FROM mailboxes WHERE address = ?', 'someone@public.test'))[0];
    return { cookie, csrf, boxId: Number(box.id), pubBoxId: Number(pubBox.id) };
  }

  it('lists private mailboxes with message count and newest, and no public ones', async () => {
    const { cookie } = await setup();
    const res = await call('GET', '/admin', { cookie });
    expectSafePageHeaders(res);
    const html = await res.text();
    expect(html).toContain('hello@private.test');
    expect(html).toMatch(/hello@private\.test<\/a><\/td>\s*<td class="num">2<\/td>/);
    expect(html).not.toContain('someone@public.test');
  });

  it('opens a mailbox and reads a message (text only, no inline HTML)', async () => {
    const { cookie, boxId } = await setup();
    const box = await (await call('GET', `/admin/mailbox?id=${boxId}`, { cookie })).text();
    expect(box).toContain('Quote request');
    expect(box).toContain('Statement');
    const msgId = (await query('SELECT id FROM messages WHERE subject = ?', 'Quote request'))[0].id;
    const page = await (await call('GET', `/admin/message?id=${msgId}`, { cookie })).text();
    expect(page).toContain('Please send a quote.');
    expect(page).toContain('client@example.com');
  });

  it('does not open public-domain mailboxes or messages', async () => {
    const { cookie, pubBoxId } = await setup();
    expect((await call('GET', `/admin/mailbox?id=${pubBoxId}`, { cookie })).status).toBe(404);
    const pubMsg = (await query('SELECT id FROM messages WHERE subject = ?', 'public mail'))[0].id;
    expect((await call('GET', `/admin/message?id=${pubMsg}`, { cookie })).status).toBe(404);
    expect((await call('GET', `/admin/message/html?id=${pubMsg}`, { cookie })).status).toBe(404);
  });

  it('escapes a hostile subject, sender and body everywhere', async () => {
    const evilSubject = '<script>alert(1)</script>"><img src=x onerror=alert(2)>';
    const evilFrom = '"><svg onload=alert(3)>@evil.test';
    await deliver({ to: 'hello@private.test', from: evilFrom, subject: evilSubject, text: '</pre><script>alert(4)</script>' });
    const cookie = await adminLogin();
    const box = (await query('SELECT id FROM mailboxes WHERE address = ?', 'hello@private.test'))[0];
    const msg = (await query('SELECT id FROM messages'))[0];
    const pages = [
      await (await call('GET', '/admin', { cookie })).text(),
      await (await call('GET', `/admin/mailbox?id=${box.id}`, { cookie })).text(),
      await (await call('GET', `/admin/message?id=${msg.id}`, { cookie })).text(),
    ];
    for (const html of pages) {
      expect(html).not.toMatch(/<script/i);
      expect(html).not.toMatch(/<img src=x/i);
      expect(html).not.toMatch(/<svg/i);
    }
    expect(pages[1]).toContain('&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(2)&gt;');
    expect(pages[2]).toContain('&quot;&gt;&lt;svg onload=alert(3)&gt;@evil.test');
    expect(pages[2]).toContain('&lt;/pre&gt;&lt;script&gt;alert(4)&lt;/script&gt;');
  });

  it('serves email HTML only from the sandboxed route', async () => {
    await deliver({
      to: 'hello@private.test', subject: 'Newsletter', text: 'text part',
      html: '<html><body><script>alert(5)</script><p class="x">Rich body</p></body></html>',
    });
    const cookie = await adminLogin();
    const msg = (await query('SELECT id FROM messages WHERE subject = ?', 'Newsletter'))[0];

    const page = await (await call('GET', `/admin/message?id=${msg.id}`, { cookie })).text();
    expect(page).not.toContain('Rich body');
    expect(page).not.toMatch(/<script/i);
    expect(page).toContain(`<iframe sandbox src="/admin/message/html?id=${msg.id}"`);

    const res = await call('GET', `/admin/message/html?id=${msg.id}`, { cookie });
    expect(res.status).toBe(200);
    const csp = res.headers.get('Content-Security-Policy') || '';
    expect(csp.startsWith('sandbox;')).toBe(true);
    for (const d of ["default-src 'none'", 'img-src data: https:', "style-src 'unsafe-inline'"]) expect(csp).toContain(d);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(await res.text()).toContain('Rich body');

    const anon = await call('GET', `/admin/message/html?id=${msg.id}`);
    expect(anon.status).toBe(401);
    expect(await anon.text()).not.toContain('Rich body');
  });

  it('deletes a message only with a valid CSRF token and Origin', async () => {
    const { cookie, csrf, boxId } = await setup();
    const msgId = String((await query('SELECT id FROM messages WHERE subject = ?', 'Statement'))[0].id);

    expect((await call('POST', '/admin/message/delete', { cookie, origin: ORIGIN, form: { id: msgId } })).status).toBe(403);
    expect((await call('POST', '/admin/message/delete', { cookie, origin: ORIGIN, form: { id: msgId, csrf: csrf + 'x' } })).status).toBe(403);
    expect((await call('POST', '/admin/message/delete', { cookie, origin: 'https://evil.test', form: { id: msgId, csrf } })).status).toBe(403);
    expect((await call('POST', '/admin/message/delete', { cookie, origin: null, form: { id: msgId, csrf } })).status).toBe(403);
    expect(await query('SELECT id FROM messages WHERE id = ?', msgId)).toHaveLength(1);

    const ok = await call('POST', '/admin/message/delete', { cookie, origin: ORIGIN, form: { id: msgId, csrf } });
    expect(ok.status).toBe(303);
    expect(ok.headers.get('Location')).toBe(`/admin/mailbox?id=${boxId}`);
    expect(await query('SELECT id FROM messages WHERE id = ?', msgId)).toHaveLength(0);
  });

  it('a CSRF token from another session does not work', async () => {
    const { cookie } = await setup();
    const other = await adminLogin('192.0.2.50');
    const otherCsrf = await csrfFrom(other);
    const msgId = String((await query('SELECT id FROM messages'))[0].id);
    expect((await call('POST', '/admin/message/delete', { cookie, origin: ORIGIN, form: { id: msgId, csrf: otherCsrf } })).status).toBe(403);
  });

  it('deletes a whole mailbox (messages and login) after confirmation', async () => {
    const { cookie, csrf, boxId } = await setup();
    await seedLegacyUser('hello@private.test', 'leftover-pw');

    const unconfirmed = await call('POST', '/admin/mailbox/delete', { cookie, origin: ORIGIN, form: { id: String(boxId), csrf } });
    expect(unconfirmed.status).toBe(400);
    expect(await query('SELECT id FROM messages WHERE mailbox_id = ?', boxId)).toHaveLength(2);

    const res = await call('POST', '/admin/mailbox/delete', { cookie, origin: ORIGIN, form: { id: String(boxId), csrf, confirm: 'yes' } });
    expect(res.status).toBe(303);
    expect(await query('SELECT id FROM mailboxes WHERE id = ?', boxId)).toHaveLength(0);
    expect(await query('SELECT id FROM messages WHERE mailbox_id = ?', boxId)).toHaveLength(0);
    expect(await query('SELECT id FROM users WHERE username = ?', 'hello@private.test')).toHaveLength(0);
    // Public mail untouched
    expect(await query('SELECT id FROM messages WHERE subject = ?', 'public mail')).toHaveLength(1);
  });

  it('refuses to delete a public mailbox', async () => {
    const { cookie, csrf, pubBoxId } = await setup();
    const res = await call('POST', '/admin/mailbox/delete', { cookie, origin: ORIGIN, form: { id: String(pubBoxId), csrf, confirm: 'yes' } });
    expect(res.status).toBe(404);
    expect(await query('SELECT id FROM mailboxes WHERE id = ?', pubBoxId)).toHaveLength(1);
  });

  it('shows public-created private-domain leftovers and deletes them', async () => {
    await seedLegacyUser('leak@private.test', 'leftover-pw');
    await seedLegacyUser('keep@public.test', 'pw');
    const cookie = await adminLogin();
    const csrf = await csrfFrom(cookie);
    const html = await (await call('GET', '/admin', { cookie })).text();
    const section = html.slice(html.indexOf('Blocked leftovers'));
    expect(section).toContain('leak@private.test');
    expect(html).not.toContain('keep@public.test');

    const leak = (await query('SELECT id FROM users WHERE username = ?', 'leak@private.test'))[0];
    const res = await call('POST', '/admin/users/delete', { cookie, origin: ORIGIN, form: { id: String(leak.id), csrf } });
    expect(res.status).toBe(303);
    expect(await query('SELECT id FROM users WHERE username = ?', 'leak@private.test')).toHaveLength(0);

    // Public users cannot be deleted from the admin portal.
    const pub = (await query('SELECT id FROM users WHERE username = ?', 'keep@public.test'))[0];
    expect((await call('POST', '/admin/users/delete', { cookie, origin: ORIGIN, form: { id: String(pub.id), csrf } })).status).toBe(404);
    expect(await query('SELECT id FROM users WHERE username = ?', 'keep@public.test')).toHaveLength(1);
  });
});
