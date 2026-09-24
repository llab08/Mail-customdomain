// The public Mail.tm-style API keeps working as before for public domains.
import { reset } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  E, call, createAccount, deliver, getToken, json, legacyJwt, query, seedLegacyUser, tokenFor,
} from './helpers';
import { createJwt } from '../authentication.js';

beforeEach(async () => {
  await reset();
});

describe('GET /domains', () => {
  it('lists only the public domains', async () => {
    const res = await call('GET', '/domains');
    expect(res.status).toBe(200);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    const body = await json(res);
    expect(body['hydra:member'].map((d: any) => d.domain)).toEqual(['public.test', 'other.test']);
    expect(body['hydra:totalItems']).toBe(2);
    expect(JSON.stringify(body)).not.toContain('private.test');
    expect(body['hydra:member'][0]).toEqual({ id: 'public.test', domain: 'public.test', isActive: true, isPrivate: false });
  });

  it('never lists a domain that is in both MAIL_DOMAIN and PRIVATE_DOMAINS', async () => {
    const env = { ...E, MAIL_DOMAIN: 'public.test,private.test', PRIVATE_DOMAINS: 'private.test' };
    const body = await json(await call('GET', '/domains', { env }));
    expect(body['hydra:member'].map((d: any) => d.domain)).toEqual(['public.test']);
  });
});

describe('public account flow', () => {
  it('create account → token → /me → receive mail → list/read/patch/delete', async () => {
    const created = await createAccount('alice@public.test', 'pw-alice-1');
    expect(created.status).toBe(200);
    const account = await json(created);
    expect(account).toMatchObject({ address: 'alice@public.test', quota: 0, used: 0, isDisabled: false, isDeleted: false });
    expect(account.id).toMatch(/^\d+$/);

    const tokenRes = await getToken('alice@public.test', 'pw-alice-1');
    expect(tokenRes.status).toBe(200);
    const { token, id } = await json(tokenRes);
    expect(id).toBe(account.id);
    expect(token.split('.')).toHaveLength(3);

    const me = await json(await call('GET', '/me', { token }));
    expect(me).toMatchObject({ id: account.id, address: 'alice@public.test' });

    // email() stores incoming mail
    await deliver({ to: 'alice@public.test', from: 'news@example.com', subject: 'Welcome', text: 'Hi Alice, welcome aboard.' });
    const list = await json(await call('GET', '/messages', { token }));
    expect(list['hydra:totalItems']).toBe(1);
    const item = list['hydra:member'][0];
    expect(item).toMatchObject({
      from: { name: '', address: 'news@example.com' },
      to: [{ name: '', address: 'alice@public.test' }],
      subject: 'Welcome',
      seen: false,
      hasAttachments: false,
    });
    expect(item.intro).toContain('Hi Alice');

    const detail = await json(await call('GET', `/messages/${item.id}`, { token }));
    expect(detail.subject).toBe('Welcome');
    expect(detail.text[0]).toContain('Hi Alice');

    const patched = await call('PATCH', `/messages/${item.id}`, { token, body: { seen: true } });
    expect(await json(patched)).toEqual({ seen: true });
    const again = await json(await call('GET', '/messages', { token }));
    expect(again['hydra:member'][0].seen).toBe(true);

    const del = await call('DELETE', `/messages/${item.id}`, { token });
    expect(del.status).toBe(204);
    const empty = await json(await call('GET', '/messages', { token }));
    expect(empty['hydra:totalItems']).toBe(0);
  });

  it('stores new passwords salted (PBKDF2), not as bare SHA-256', async () => {
    await createAccount('salt@public.test', 'same-password');
    await createAccount('salt2@public.test', 'same-password');
    const rows = await query<{ password_hash: string }>('SELECT password_hash FROM users ORDER BY id');
    expect(rows[0].password_hash).toMatch(/^pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
    expect(rows[0].password_hash).not.toBe(rows[1].password_hash);
  });

  it('keeps legacy SHA-256 users working and upgrades their hash on login', async () => {
    await seedLegacyUser('old@public.test', 'old-password');
    const before = await query('SELECT password_hash FROM users WHERE username = ?', 'old@public.test');
    expect(before[0].password_hash).toMatch(/^[0-9a-f]{64}$/);

    const token = await tokenFor('old@public.test', 'old-password');
    expect((await call('GET', '/me', { token })).status).toBe(200);

    const after = await query('SELECT password_hash FROM users WHERE username = ?', 'old@public.test');
    expect(after[0].password_hash).toMatch(/^pbkdf2-sha256\$/);
    expect((await getToken('old@public.test', 'old-password')).status).toBe(200);
    expect((await getToken('old@public.test', 'wrong')).status).toBe(401);
  });

  it('keeps tokens issued by the previous Worker valid for public users', async () => {
    const { mailboxId, userId } = await seedLegacyUser('legacy@public.test', 'pw');
    const token = await legacyJwt('legacy@public.test', mailboxId, userId);
    const me = await call('GET', '/me', { token });
    expect(me.status).toBe(200);
    expect((await json(me)).address).toBe('legacy@public.test');
  });

  it('rejects bad input like before', async () => {
    expect((await createAccount('x@unknown.test', 'pw')).status).toBe(400);
    expect((await call('POST', '/accounts', { body: { address: 'x@public.test' } })).status).toBe(400);
    expect((await createAccount('a@b@public.test', 'pw')).status).toBe(400);
    expect((await call('POST', '/accounts', { body: 'not json' })).status).toBe(400);
    expect((await call('POST', '/token', { body: {} })).status).toBe(400);
    expect((await call('GET', '/nope', { token: 'x.y.z' })).status).toBe(401);
  });

  it('answers CORS preflight', async () => {
    const res = await call('OPTIONS', '/accounts');
    expect(res.status).toBe(204);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
  });
});

describe('existing address', () => {
  it('POST /accounts for a taken address answers 422 and keeps the old password', async () => {
    expect((await createAccount('bob@public.test', 'bob-original')).status).toBe(200);

    const dup = await createAccount('bob@public.test', 'attacker-password');
    expect(dup.status).toBe(422);
    const body = await json(dup);
    expect(body.violations[0]).toEqual({ propertyPath: 'address', message: 'This value is already used.' });

    expect((await getToken('bob@public.test', 'bob-original')).status).toBe(200);
    expect((await getToken('bob@public.test', 'attacker-password')).status).toBe(401);
  });

  it('treats a different letter case as the same address', async () => {
    await createAccount('carol@public.test', 'carol-pw');
    expect((await createAccount('Carol@Public.TEST', 'x')).status).toBe(422);
    expect((await createAccount(' carol@public.test ', 'x')).status).toBe(422);
    expect((await getToken('carol@public.test', 'carol-pw')).status).toBe(200);
  });

  it('refuses to overwrite a legacy (pre-deploy) user as well', async () => {
    await seedLegacyUser('dave@public.test', 'dave-pw');
    expect((await createAccount('dave@public.test', 'new')).status).toBe(422);
    expect((await getToken('dave@public.test', 'dave-pw')).status).toBe(200);
  });

  it('refuses to create a lower-case twin of a legacy user stored as typed (mixed case or spaces)', async () => {
    // The previous Worker stored the username exactly as typed; mailboxes were always lower-case.
    for (const [stored, attempt] of [['Victim@public.test', 'victim@public.test'], [' spacey@public.test', 'spacey@public.test']]) {
      await seedLegacyUser(stored, 'victim-password');
      await deliver({ to: attempt, subject: 'victim secret' });
      const res = await createAccount(attempt, 'attacker-password');
      expect(res.status, stored).toBe(422);
      expect((await getToken(attempt, 'attacker-password')).status, stored).toBe(401);
      // The owner still logs in, in the old spelling and the normalized one.
      expect((await getToken(stored, 'victim-password')).status, stored).toBe(200);
      expect((await getToken(attempt, 'victim-password')).status, stored).toBe(200);
    }
    expect((await query('SELECT id FROM users')).length).toBe(2);
  });

  it('with duplicate legacy rows for one mailbox, the oldest login wins and newer ones get no access', async () => {
    const victim = await seedLegacyUser('Dup@public.test', 'victim-password');
    await deliver({ to: 'dup@public.test', subject: 'victim secret' });
    // A lower-case twin the old Worker could still create before the deploy.
    const intruder = await seedLegacyUser('dup@public.test', 'intruder-password');
    expect(intruder.mailboxId).toBe(victim.mailboxId);

    expect((await getToken('dup@public.test', 'intruder-password')).status).toBe(401);
    const oldIntruderToken = await legacyJwt('dup@public.test', intruder.mailboxId, intruder.userId);
    expect((await call('GET', '/messages', { token: oldIntruderToken })).status).toBe(401);

    const token = await tokenFor('dup@public.test', 'victim-password');
    const list = await json(await call('GET', '/messages', { token }));
    expect(list['hydra:member'].map((m: any) => m.subject)).toEqual(['victim secret']);
    const oldVictimToken = await legacyJwt('Dup@public.test', victim.mailboxId, victim.userId);
    expect((await call('GET', '/me', { token: oldVictimToken })).status).toBe(200);
  });

  it('still lets someone claim a mailbox that only received mail (no login yet)', async () => {
    await deliver({ to: 'fresh@public.test', subject: 'early' });
    expect((await createAccount('fresh@public.test', 'pw')).status).toBe(200);
    const token = await tokenFor('fresh@public.test', 'pw');
    expect((await json(await call('GET', '/messages', { token })))['hydra:totalItems']).toBe(1);
  });
});

describe('token re-check on every request', () => {
  it('refuses a token whose user was deleted', async () => {
    await createAccount('gone@public.test', 'pw');
    const token = await tokenFor('gone@public.test', 'pw');
    await E.TEMP_MAIL_DB.prepare('DELETE FROM users WHERE username = ?').bind('gone@public.test').run();
    expect((await call('GET', '/messages', { token })).status).toBe(401);
  });

  it('refuses a token that points at another mailbox', async () => {
    await createAccount('eve@public.test', 'pw');
    await deliver({ to: 'victim@public.test', subject: 'secret' });
    const eve = (await query('SELECT id FROM users WHERE username = ?', 'eve@public.test'))[0];
    const victimBox = (await query('SELECT id FROM mailboxes WHERE address = ?', 'victim@public.test'))[0];
    const forged = await legacyJwt('eve@public.test', Number(victimBox.id), Number(eve.id));
    expect((await call('GET', '/messages', { token: forged })).status).toBe(401);
  });
});

describe('token signing key', () => {
  it('fails closed without JWT_SECRET: the old public JWT_TOKEN var is never used', async () => {
    await createAccount('kim@public.test', 'pw');
    const good = await tokenFor('kim@public.test', 'pw');
    const leaked = 'value-that-was-in-the-public-wrangler-toml';
    for (const env of [{ ...E, JWT_SECRET: undefined, JWT_TOKEN: leaked }, { ...E, JWT_SECRET: 'too-short', JWT_TOKEN: leaked }]) {
      expect((await call('POST', '/token', { body: { address: 'kim@public.test', password: 'pw' }, env })).status).toBe(503);
      const user = (await query('SELECT id FROM users WHERE username = ?', 'kim@public.test'))[0];
      const box = (await query('SELECT id FROM mailboxes WHERE address = ?', 'kim@public.test'))[0];
      const forged = await createJwt(leaked, { address: 'kim@public.test', mailboxId: Number(box.id), userId: Number(user.id) });
      expect((await call('GET', '/me', { token: forged, env })).status).toBe(503);
      expect((await call('GET', '/me', { token: good, env })).status).toBe(503);
    }
    // With the real secret, a token signed with the old value is refused.
    const user = (await query('SELECT id FROM users WHERE username = ?', 'kim@public.test'))[0];
    const box = (await query('SELECT id FROM mailboxes WHERE address = ?', 'kim@public.test'))[0];
    const forged = await createJwt(leaked, { address: 'kim@public.test', mailboxId: Number(box.id), userId: Number(user.id) });
    expect((await call('GET', '/me', { token: forged, env: { ...E, JWT_TOKEN: leaked } })).status).toBe(401);
    expect((await call('GET', '/me', { token: good })).status).toBe(200);
  });
});
