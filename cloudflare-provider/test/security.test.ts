// Unit tests for the helpers in security.ts.
import { describe, expect, it } from 'vitest';
import {
  forwardTarget, hashPassword, isPrivateAddress, publicDomains, sha256Hex, splitAddress, timingSafeEqual, verifyPassword,
  bytesToB64, rateKeyForIp, signClientIp, limitClientIp, CLIENT_IP_HEADER, CLIENT_IP_SIGNATURE_HEADER,
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

describe('rate-limit keys per client', () => {
  it('keeps IPv4 addresses whole', () => {
    expect(rateKeyForIp('198.51.100.7')).toBe('198.51.100.7');
    expect(rateKeyForIp('198.51.100.8')).toBe('198.51.100.8');
  });

  it('groups IPv6 addresses by /64, in every spelling', () => {
    const key = '2001:db8:1:2::/64';
    for (const ip of ['2001:db8:1:2::1', '2001:db8:1:2::1e', '2001:0DB8:0001:0002:ffff:ffff:ffff:ffff', '2001:db8:1:2:0:0:0:9', '2001:db8:1:2::1%eth0']) {
      expect(rateKeyForIp(ip), ip).toBe(key);
    }
    expect(rateKeyForIp('2001:db8:1:3::1')).toBe('2001:db8:1:3::/64');
    expect(rateKeyForIp('::1')).toBe('0:0:0:0::/64');
  });

  it('counts IPv4-mapped IPv6 as the IPv4 address', () => {
    expect(rateKeyForIp('::ffff:198.51.100.7')).toBe('198.51.100.7');
  });

  it('keeps anything unparsable as it is', () => {
    expect(rateKeyForIp('unknown')).toBe('unknown');
    expect(rateKeyForIp('1:2:3')).toBe('1:2:3');
    expect(rateKeyForIp('')).toBe('unknown');
  });
});

describe('signed client IP from the web-app proxy', () => {
  const secret = 'test-client-ip-secret-not-real-0123456789';
  const now = 1790000000;
  const req = (headers: Record<string, string>) =>
    new Request('https://worker.test/token', { method: 'POST', headers: { 'CF-Connecting-IP': '203.0.113.99', ...headers } });

  it('matches the signature the Next.js proxy computes (node:crypto createHmac, base64url)', async () => {
    // Vector computed with lib/client-ip-signature.ts's algorithm in Node.
    expect(await signClientIp(secret, '2001:db8::7', now)).toBe('v1.1790000000.x6rssTwbJl5z4-pRJO1QO95kTzSNZRgpQcz7sOCtHVQ');
  });

  it('uses the header only with a valid, fresh signature', async () => {
    const good = await signClientIp(secret, '198.51.100.20', now);
    const env = { CLIENT_IP_SECRET: secret };
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: good }), env, now)).toBe('198.51.100.20');
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: good }), env, now + 299)).toBe('198.51.100.20');
    // stale or from the future
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: good }), env, now + 301)).toBe('203.0.113.99');
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: good }), env, now - 301)).toBe('203.0.113.99');
    // signature for another IP, tampered, missing, wrong secret
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.21', [CLIENT_IP_SIGNATURE_HEADER]: good }), env, now)).toBe('203.0.113.99');
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: good.slice(0, -1) + 'A' }), env, now)).toBe('203.0.113.99');
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20' }), env, now)).toBe('203.0.113.99');
    const other = await signClientIp(secret + 'x', '198.51.100.20', now);
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: other }), env, now)).toBe('203.0.113.99');
    // not an IP
    const junk = await signClientIp(secret, 'x<y>', now);
    expect(await limitClientIp(req({ [CLIENT_IP_HEADER]: 'x<y>', [CLIENT_IP_SIGNATURE_HEADER]: junk }), env, now)).toBe('203.0.113.99');
  });

  it('ignores the header when CLIENT_IP_SECRET is missing or short', async () => {
    const good = await signClientIp(secret, '198.51.100.20', now);
    const headers = { [CLIENT_IP_HEADER]: '198.51.100.20', [CLIENT_IP_SIGNATURE_HEADER]: good };
    expect(await limitClientIp(req(headers), {}, now)).toBe('203.0.113.99');
    expect(await limitClientIp(req(headers), { CLIENT_IP_SECRET: 'short' }, now)).toBe('203.0.113.99');
  });
});
