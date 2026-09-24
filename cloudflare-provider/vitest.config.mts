// Runs the Worker inside the local Workers runtime (workerd via Miniflare)
// with a throwaway local D1 database. No Cloudflare account or network needed.
import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// Test-only admin password; hashed here exactly like owner-deploy-tempmail.sh does.
const TEST_ADMIN_PASSWORD = 'test-admin-password-not-real';
const ITERATIONS = 100000;
const salt = randomBytes(16);
const hash = pbkdf2Sync(TEST_ADMIN_PASSWORD, salt, ITERATIONS, 32, 'sha256');

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: './worker.ts',
      remoteBindings: false,
      miniflare: {
        compatibilityDate: '2024-12-01',
        d1Databases: ['TEMP_MAIL_DB'],
        bindings: {
          MAIL_DOMAIN: 'public.test other.test',
          PRIVATE_DOMAINS: 'private.test',
          JWT_SECRET: 'test-jwt-secret-not-real',
          ADMIN_PASSWORD_HASH: `pbkdf2-sha256$${ITERATIONS}$${salt.toString('base64')}$${hash.toString('base64')}`,
          ADMIN_SESSION_SECRET: 'test-session-secret-not-real-0123456789abcdef',
          FORWARD_RULES: JSON.stringify({ 'hello@private.test': 'owner@forward.test' }),
          TEST_ADMIN_PASSWORD,
        },
      },
    }),
  ],
  test: {
    include: ['test/**/*.test.ts'],
  },
});
