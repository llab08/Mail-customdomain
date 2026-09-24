# Duckmail Cloudflare Provider

This is a Cloudflare Worker-based email provider for Duckmail that implements the Hydra API.

## Prerequisites

1. A Cloudflare account
2. A domain configured with Cloudflare
3. Node.js and npm/pnpm installed
4. Wrangler CLI (will be installed with dependencies)

## Setup Instructions

### 1. Install Dependencies

```bash
cd cloudflare-provider
npm install
# or
pnpm install
```

### 2. Create D1 Database

```bash
# Create a new D1 database
wrangler d1 create temp_mail_db

# Copy the database_id from the output and update wrangler.toml
```

### 3. Configure wrangler.toml

Update the `wrangler.toml` file with your configuration:

- Replace `<your-d1-database-id>` with the database ID from step 2
- Replace `yourdomain.com` with your actual domain(s)
- Set `MAIL_DOMAIN` (public) and `PRIVATE_DOMAINS` (private)
- Set the secrets: `wrangler secret put JWT_SECRET`, `ADMIN_PASSWORD_HASH`, `ADMIN_SESSION_SECRET`

### 4. Deploy the Worker

```bash
# Deploy to Cloudflare
wrangler deploy

# Note the worker URL from the output (e.g., https://duckmail-cloudflare-provider.your-subdomain.workers.dev)
```

### 5. Configure Email Routing

1. Go to Cloudflare Dashboard → Email → Email Routing
2. Add your domain if not already configured
3. Create a catch-all rule:
   - Match: `*@yourdomain.com`
   - Action: Send to Worker
   - Worker: Select `duckmail-cloudflare-provider`

### 6. Update Duckmail Configuration

Update the Cloudflare provider URL in `lib/api.ts`:

```typescript
{
  id: "cloudflare",
  name: "Cloudflare",
  baseUrl: "https://your-actual-worker-url.workers.dev", // Replace with your worker URL
  mercureUrl: "", // No SSE support initially
}
```

## Development

### Local Testing

```bash
# Run locally with Wrangler
wrangler dev

# The worker will be available at http://localhost:8787
```

### Database Initialization

The database schema is automatically initialized on the first request. The schema includes:

- `mailboxes`: Stores email addresses
- `messages`: Stores email messages
- `users`: Stores user authentication

### Testing the API

1. Get available domains:
   ```bash
   curl http://localhost:8787/domains
   ```

2. Create an account:
   ```bash
   curl -X POST http://localhost:8787/accounts \
     -H "Content-Type: application/json" \
     -d '{"address": "test@yourdomain.com", "password": "testpass"}'
   ```

3. Get auth token:
   ```bash
   curl -X POST http://localhost:8787/token \
     -H "Content-Type: application/json" \
     -d '{"address": "test@yourdomain.com", "password": "testpass"}'
   ```

4. Get messages (with Bearer token):
   ```bash
   curl http://localhost:8787/messages \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```

## Environment Variables

Plain variables (`wrangler.toml` → `[vars]`):

- `MAIL_DOMAIN`: public domains (space or comma separated). Listed by `GET /domains`; anyone can create an account.
- `PRIVATE_DOMAINS`: private domains. Mail is still received and stored, but `GET /domains` never lists them, `POST /accounts` answers 403, and `/token` plus every authenticated endpoint refuse addresses on them unless the login was created by the admin (role `private`). Read this mail in the admin portal.
- `FORWARD_RULES`: optional JSON object `{"address": "verified destination"}`. Matching mail is stored first, then forwarded with `message.forward()`; a failed forward never loses the stored copy.

Secrets (`wrangler secret put <NAME>`, never in `wrangler.toml`):

- `JWT_SECRET`: signs API tokens. (`JWT_TOKEN` is still read as a fallback for old setups.)
- `ADMIN_PASSWORD_HASH`: `pbkdf2-sha256$<iterations>$<salt base64>$<hash base64>` of the admin password. Workers accept at most 100,000 PBKDF2 iterations.
- `ADMIN_SESSION_SECRET`: at least 32 random characters; signs the admin session cookie.
- `RESEND_API_KEY`: not used by the Worker.

## Admin portal

`https://<worker>/admin` — one admin password, a 12-hour session cookie (`HttpOnly; Secure; SameSite=Strict; Path=/admin`), sign out. Pages:

- private mailboxes (address, message count, newest), open a mailbox, read a message, delete a message or a whole mailbox;
- "blocked leftovers": logins on private domains that were created through the public API — they can no longer sign in and can be deleted;
- optional app logins for a private address (role `private`).

Every POST needs the same `Origin` and a per-session CSRF token. Failed admin logins are limited to 10 per IP per 15 minutes. Email HTML is never inlined: it is served from `/admin/message/html` with `Content-Security-Policy: sandbox; default-src 'none'; img-src data: https:; style-src 'unsafe-inline'` inside an `<iframe sandbox>`. The admin portal cannot open public-domain mailboxes.

## Abuse limits

- `POST /accounts` for an address that already has a login answers 422 (Mail.tm "This value is already used."); passwords are never reset through it.
- `POST /token`: 10 failed logins per 15 minutes per IP and address, 100 per IP overall (the DuckMail web app proxies all its users through its own server IP). Stored in the D1 table `auth_failures` as SHA-256 keys only.
- New passwords are stored as salted PBKDF2; old unsalted SHA-256 hashes still verify and are upgraded on the next successful login.

## Tests

```bash
npm install
npm test          # vitest + @cloudflare/vitest-pool-workers: local workerd + local D1, no Cloudflare account needed
npm run typecheck
```

## Troubleshooting

1. **Database not found**: Make sure you've created the D1 database and updated the database_id in wrangler.toml
2. **Email routing not working**: Verify your domain's Email Routing is properly configured in Cloudflare
3. **Authentication errors**: Check that your JWT secret is properly set and consistent

## Notes

- SSE/Mercure support is not implemented initially - Duckmail will use polling
- The worker implements bearer token authentication (no cookies)
- All Hydra API endpoints are implemented according to the Mail.tm spec 