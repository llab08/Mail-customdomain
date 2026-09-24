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
- Set the secrets: `wrangler secret put JWT_SECRET`, `ADMIN_PASSWORD_HASH`, `ADMIN_SESSION_SECRET`, `CLIENT_IP_SECRET` (the same `CLIENT_IP_SECRET` value also goes into the web app's server environment)

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

- `JWT_SECRET`: signs API tokens; at least 32 characters. Required: without it `/token` and every authenticated endpoint answer 503. The old `JWT_TOKEN` var is **not** read any more — its value is in this public repository's history, so tokens signed with it are forgeable.
- `ADMIN_PASSWORD_HASH`: `pbkdf2-sha256$<iterations>$<salt base64>$<hash base64>` of the admin password. Workers accept at most 100,000 PBKDF2 iterations.
- `ADMIN_SESSION_SECRET`: at least 32 random characters; signs the admin session cookie.
- `CLIENT_IP_SECRET`: at least 32 random characters, shared with the DuckMail web app (server env var `CLIENT_IP_SECRET`, not `NEXT_PUBLIC_`). The app's `/api/mail` proxy sends each browser's IP in `X-DuckMail-Client-IP` with `X-DuckMail-Client-IP-Signature: v1.<unix time>.<base64url HMAC-SHA256(secret, "v1.<time>.<ip>")>`; the Worker uses that IP for the `/token` limits only when the signature is valid and at most 5 minutes old, otherwise `CF-Connecting-IP`.
- `RESEND_API_KEY`: not used by the Worker.

## Admin portal

`https://<worker>/admin` — one admin password, a 12-hour session cookie (`HttpOnly; Secure; SameSite=Strict; Path=/admin`), sign out. Pages:

- private mailboxes (address, message count, newest), open a mailbox, read a message, delete a message or a whole mailbox;
- "blocked leftovers": logins on private domains that were created through the public API — they can no longer sign in and can be deleted;
- optional app logins for a private address (role `private`).

Every POST needs the same `Origin` and a per-session CSRF token. Failed admin logins are limited to 10 per 15 minutes per IPv4 address or IPv6 /64, and to 30 per 15 minutes from all sources together (then the login page answers 429 for everyone until the window ends; signed-in sessions keep working; `npx wrangler d1 execute temp_mail_db --remote --command "DELETE FROM auth_failures"` clears it early). The mailbox list pages 100 at a time, has an address search, and lists mailboxes with an app login or a `FORWARD_RULES` entry first. Email HTML is never inlined: it is served from `/admin/message/html` with `Content-Security-Policy: sandbox; default-src 'none'; img-src data: https:; style-src 'unsafe-inline'` inside an `<iframe sandbox>`. The admin portal cannot open public-domain mailboxes.

## Abuse limits

- `POST /accounts` for an address that already has a login answers 422 (Mail.tm "This value is already used."); passwords are never reset through it.
- `POST /token`: 10 failed logins per 15 minutes per client and address, 100 per client overall. The client is the browser IP signed by the web app's proxy (see `CLIENT_IP_SECRET`), else `CF-Connecting-IP`; IPv6 counts per /64. Each attempt is counted atomically *before* the password is checked (one D1 batch: `INSERT … ON CONFLICT DO UPDATE … RETURNING count`), so parallel requests cannot exceed the limits; successful logins are refunded. Stored in the D1 table `auth_failures` as SHA-256 keys only.
- Logins are matched on `lower(trim(username))` (index `idx_users_username_norm`); when old data holds several rows for one address, the oldest wins, so a later twin such as `victim@` next to a legacy `Victim@` gets neither a token nor the mailbox.
- New passwords are stored as salted PBKDF2; old unsalted SHA-256 hashes still verify and are upgraded on the next successful login.

## D1 rows read

D1 bills (and on the free plan, caps at 5,000,000 per day) every row a statement *reads*, not the rows it returns. The Worker therefore:

- checks the schema once per isolate (one `sqlite_master` lookup of the newest index, ~20 rows) and runs the full, idempotent migration in `database.js` only when that index is missing — never on every request;
- keeps every request on indexes: `idx_users_username_norm` for logins and token re-checks, `idx_messages_mailbox_received (mailbox_id, received_at)` for message lists and counts, `idx_auth_failures_window_start` for the bounded cleanup of old failure counters (at most 50 rows per attempt);
- builds the admin mailbox list from one pass over the mailbox addresses plus a few index rows per private mailbox, and counts messages only for the mailboxes on the shown page.

On production-like volumes (5,000 mailboxes, 5,000 users, 7,500 messages) an API request reads at most ~35 rows (most 0–10) and an email delivery 6. What still grows with the data:
- `GET /messages` reads the messages up to the requested page and, when that page is full, one index row per message of that mailbox for `hydra:totalItems` (a 300-message inbox: ~330 rows per call; the web app polls page 1 every 30 s per open tab);
- `POST /token` and `/admin/login` read up to ~200 more rows while a backlog of expired failure counters is being cleaned (50 per attempt);
- `/admin` reads every mailbox address and every username once, plus ~3 index rows per private mailbox (~12,000 rows with 200 private mailboxes, ~18,000 with 1,500); `/admin/mailbox` counts that mailbox's messages;
- the first request after deploying this version builds `idx_messages_mailbox_received` once (~2 rows read and 1 written per message). An isolate of the previous version that serves a request during the rollout may re-create the old `idx_messages_mailbox_id`; that is harmless (one more index row written per new message) and `DROP INDEX idx_messages_mailbox_id` removes it.

`test/d1-reads.test.ts` enforces these budgets; print the table with every statement:

```bash
D1_READS_REPORT=1 npx vitest run test/d1-reads.test.ts --reporter=verbose
```

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