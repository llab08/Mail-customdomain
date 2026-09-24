// Unit tests for the helpers in security.ts.
import { describe, expect, it } from 'vitest';
import {
  forwardTarget, hashPassword, isPrivateAddress, publicDomains, sha256Hex, splitAddress, timingSafeEqual, verifyPassword,
  bytesToB64,
} from '../security';

async function pbkdf2Hash(password: string, iterations: number): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return `pbkdf2-sha256$${iterations}$${bytesToB64(salt)}$${bytesToB64(new Uint8Array(bits))}`;
}

describe('passwords', () => {
  it('round-trips PBKDF2 hashes', async () => {
    const h = await hashPassword('s3cret');
    expect(await verifyPassword('s3cret', h)).toBe(true);
    expect(await verifyPassword('s3cret ', h)).toBe(false);
  });

  it('accepts legacy SHA-256 hex hashes', async () => {
    const legacy = await sha256Hex('old');
    expect(await verifyPassword('old', legacy)).toBe(true);
    expect(await verifyPassword('old', legacy.toUpperCase())).toBe(true);
    expect(await verifyPassword('new', legacy)).toBe(false);
  });

  it('accepts the admin hash format the deploy script writes (100,000 iterations)', async () => {
    expect(await verifyPassword('admin pw', await pbkdf2Hash('admin pw', 100000))).toBe(true);
  });

  it('refuses iteration counts above the Workers limit instead of throwing', async () => {
    expect(await verifyPassword('admin pw', await pbkdf2Hash('admin pw', 310000))).toBe(false);
  });

  it('refuses malformed hashes', async () => {
    for (const bad of [null, '', 'plain', 'pbkdf2-sha256$x$y$z', 'pbkdf2-sha256$1000$!!$!!', 'md5$1$a$b']) {
      expect(await verifyPassword('x', bad)).toBe(false);
    }
  });

  it('compares in constant time', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
  });
});

describe('domains', () => {
  const env = { MAIL_DOMAIN: 'Public.test, other.test private.test', PRIVATE_DOMAINS: 'private.test' };

  it('private wins over public', () => {
    expect(publicDomains(env)).toEqual(['public.test', 'other.test']);
  });

  it('detects private addresses case-insensitively, including subdomains', () => {
    expect(isPrivateAddress(env, 'Hello@PRIVATE.test')).toBe(true);
    expect(isPrivateAddress(env, 'x@mail.private.test')).toBe(true);
    expect(isPrivateAddress(env, '"a@public.test"@private.test')).toBe(true);
    expect(isPrivateAddress(env, 'x@notprivate.test')).toBe(false);
    expect(isPrivateAddress(env, 'x@public.test')).toBe(false);
    expect(isPrivateAddress({}, 'x@private.test')).toBe(false);
  });

  it('splits addresses strictly', () => {
    expect(splitAddress(' A@B.test ')).toEqual({ local: 'a', domain: 'b.test' });
    expect(splitAddress('a@b@c')).toBeNull();
    expect(splitAddress('@b')).toBeNull();
    expect(splitAddress('a@')).toBeNull();
    expect(splitAddress(42)).toBeNull();
  });
});

describe('FORWARD_RULES', () => {
  it('maps exact addresses, ignores everything else', () => {
    const env = { FORWARD_RULES: '{"Hello@private.test":"me@dest.test","bad@private.test":42}' };
    expect(forwardTarget(env, 'hello@PRIVATE.test')).toBe('me@dest.test');
    expect(forwardTarget(env, 'hello2@private.test')).toBeNull();
    expect(forwardTarget(env, 'bad@private.test')).toBeNull();
    expect(forwardTarget({}, 'hello@private.test')).toBeNull();
    expect(forwardTarget({ FORWARD_RULES: 'not json' }, 'hello@private.test')).toBeNull();
    expect(forwardTarget({ FORWARD_RULES: '[]' }, 'hello@private.test')).toBeNull();
  });
});
