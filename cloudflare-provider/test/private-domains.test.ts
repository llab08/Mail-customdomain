// Private domains: mail is received and stored, but the public API cannot
// create, log in to, or keep using addresses on them.
import { reset } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  ORIGIN, adminLogin, call, createAccount, csrfFrom, deliver, getToken, json, legacyJwt, query, seedLegacyUser, tokenFor,
} from './helpers';

beforeEach(async () => {
  await reset();
});

describe('POST /accounts on a private domain', () => {
  it('answers 403 in every spelling', async () => {
    for (const address of ['hello@private.test', 'HELLO@Private.Test', ' admin@private.test', 'x@sub.private.test']) {
      const res = await createAccount(address, 'pw');
      expect(res.status, address).toBe(403);
    }
    expect(await query('SELECT id FROM users')).toHaveLength(0);
    expect(await query('SELECT id FROM mailboxes')).toHaveLength(0);
  });
});

describe('receiving mail for a private domain', () => {
  it('stores it and forwards it when FORWARD_RULES has the address', async () => {
    const { forward } = await deliver({ to: 'hello@private.test', subject: 'Contract' });
    expect(forward).toHaveBeenCalledWith('owner@forward.test');
    const rows = await query(
      'SELECT msg.subject FROM messages msg JOIN mailboxes m ON m.id = msg.mailbox_id WHERE m.address = ?', 'hello@private.test');
    expect(rows.map(r => r.subject)).toEqual(['Contract']);
  });

  it('keeps the stored copy when forwarding fails', async () => {
    const { forward } = await deliver({
      to: 'hello@private.test', subject: 'Keep me',
      forward: async () => { throw new Error('destination not verified'); },
    });
    expect(forward).toHaveBeenCalledTimes(1);
    expect(await query('SELECT id FROM messages WHERE subject = ?', 'Keep me')).toHaveLength(1);
  });

  it('does not forward addresses without a rule', async () => {
    const { forward } = await deliver({ to: 'other@private.test' });
    expect(forward).not.toHaveBeenCalled();
    expect(await query('SELECT id FROM messages')).toHaveLength(1);
  });
});

describe('a private-domain login created through the public API before the deploy', () => {
  it('can no longer get a token, even with the right password', async () => {
    await seedLegacyUser('leak@private.test', 'known-password');
    const res = await getToken('leak@private.test', 'known-password');
    expect(res.status).toBe(401);
    expect(await json(res)).toEqual({ error: 'Invalid credentials' });
  });

  it('loses access with a JWT issued before the deploy', async () => {
    const { mailboxId, userId } = await seedLegacyUser('leak@private.test', 'known-password');
    await deliver({ to: 'leak@private.test', subject: 'private mail' });
    const oldToken = await legacyJwt('leak@private.test', mailboxId, userId);
    for (const path of ['/me', '/messages']) {
      expect((await call('GET', path, { token: oldToken })).status, path).toBe(401);
    }
    const msg = (await query('SELECT id FROM messages'))[0];
    expect((await call('GET', `/messages/${msg.id}`, { token: oldToken })).status).toBe(401);
    expect((await call('DELETE', `/messages/${msg.id}`, { token: oldToken })).status).toBe(401);
    expect(await query('SELECT id FROM messages')).toHaveLength(1);
  });

  it('cannot re-register the address to reset the password', async () => {
    await seedLegacyUser('leak@private.test', 'known-password');
    expect((await createAccount('leak@private.test', 'new')).status).toBe(403);
  });
});

describe('an app login created by the admin', () => {
  it('works for the private address and stops working once removed', async () => {
    const cookie = await adminLogin();
    const csrf = await csrfFrom(cookie);
    const created = await call('POST', '/admin/users/create', {
      cookie, origin: ORIGIN, form: { csrf, address: 'team@private.test', password: 'a-long-team-password' },
    });
    expect(created.status).toBe(303);
    const user = (await query('SELECT id, role, password_hash FROM users WHERE username = ?', 'team@private.test'))[0];
    expect(user.role).toBe('private');
    expect(user.password_hash).toMatch(/^pbkdf2-sha256\$/);

    await deliver({ to: 'team@private.test', subject: 'for the team' });
    const token = await tokenFor('team@private.test', 'a-long-team-password');
    const list = await json(await call('GET', '/messages', { token }));
    expect(list['hydra:member'][0].subject).toBe('for the team');

    const removed = await call('POST', '/admin/users/delete', { cookie, origin: ORIGIN, form: { csrf, id: String(user.id) } });
    expect(removed.status).toBe(303);
    expect((await call('GET', '/messages', { token })).status).toBe(401);
    expect((await getToken('team@private.test', 'a-long-team-password')).status).toBe(401);
  });

  it('re-creating a login invalidates tokens of the previous one', async () => {
    const cookie = await adminLogin();
    const csrf = await csrfFrom(cookie);
    const make = (password: string) => call('POST', '/admin/users/create', {
      cookie, origin: ORIGIN, form: { csrf, address: 'team@private.test', password },
    });
    await make('first-long-password');
    const first = await tokenFor('team@private.test', 'first-long-password');
    await make('second-long-password');
    expect((await call('GET', '/me', { token: first })).status).toBe(401);
    expect((await getToken('team@private.test', 'first-long-password')).status).toBe(401);
    expect((await getToken('team@private.test', 'second-long-password')).status).toBe(200);
  });

  it('only accepts private-domain addresses and long passwords', async () => {
    const cookie = await adminLogin();
    const csrf = await csrfFrom(cookie);
    const pub = await call('POST', '/admin/users/create', { cookie, origin: ORIGIN, form: { csrf, address: 'x@public.test', password: 'a-long-password-1' } });
    expect(pub.status).toBe(400);
    const short = await call('POST', '/admin/users/create', { cookie, origin: ORIGIN, form: { csrf, address: 'x@private.test', password: 'short' } });
    expect(short.status).toBe(400);
    expect(await query('SELECT id FROM users')).toHaveLength(0);
  });
});
