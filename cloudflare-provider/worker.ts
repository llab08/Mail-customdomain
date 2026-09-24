import type { EmailMessage } from '@cloudflare/workers-types';
import { ensureSchema, getOrCreateMailboxId, getMailboxIdByAddress } from './database.js';
import { createJwt, verifyJwt, base64UrlDecode } from './authentication.js';
import { parseEmailBody } from './emailParser.js';
import { handleAdmin } from './admin';
import {
  USER_PBKDF2_ITERATIONS,
  findUserByAddress,
  forwardTarget,
  hashPassword,
  isLegacyHash,
  isPrivateAddress,
  limitClientIp,
  normalizeAddress,
  publicDomains,
  rateKeyForIp,
  settleSuccess,
  splitAddress,
  takeAttempt,
  tokenStillValid,
  userMayUseAddress,
  verifyPassword,
} from './security';

interface Env {
  TEMP_MAIL_DB: D1Database;
  /** Public domains: listed by /domains, anyone may create accounts. */
  MAIL_DOMAIN: string;
  /** Private domains: mail is stored, only the admin portal (or admin-created logins) can read it. */
  PRIVATE_DOMAINS?: string;
  /**
   * Signs the API tokens (secret, 32+ characters). Required: the old JWT_TOKEN
   * var is NOT used as a fallback, because its value is in the public repo
   * history and anyone could sign tokens with it.
   */
  JWT_SECRET?: string;
  /**
   * Shared with the DuckMail web app (secret, 32+ characters): lets its
   * /api/mail proxy pass the browser's IP for the /token failure limits.
   */
  CLIENT_IP_SECRET?: string;
  /** pbkdf2-sha256$<iterations>$<salt b64>$<hash b64> of the admin password (secret). */
  ADMIN_PASSWORD_HASH?: string;
  /** HMAC key for the admin session cookie (secret, 32+ chars). */
  ADMIN_SESSION_SECRET?: string;
  /** Optional JSON object {"address":"verified destination"} for message.forward(). */
  FORWARD_RULES?: string;
  RESEND_API_KEY?: string;
}

/** Failed /token logins allowed per 15 minutes for one address from one client. */
const TOKEN_FAILURES_PER_IP_AND_ADDRESS = 10;
/** Failed /token logins allowed per 15 minutes from one client across all addresses. */
const TOKEN_FAILURES_PER_IP = 100;
/** Shortest JWT_SECRET the Worker accepts; the deploy script sets a 64-character one. */
const MIN_JWT_SECRET_LENGTH = 32;

/** The token signing key, or null when it is missing or too short (the Worker then fails closed). */
function jwtSecretOf(env: Env): string | null {
  const secret = env.JWT_SECRET;
  return typeof secret === 'string' && secret.length >= MIN_JWT_SECRET_LENGTH ? secret : null;
}

// Bearer token verification function
async function verifyBearerToken(authHeader: string | null, secret: string): Promise<any> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }
  
  const token = authHeader.substring(7);
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = base64UrlDecode(parts[2]);
    const data = encoder.encode(parts[0] + '.' + parts[1]);
    const valid = await crypto.subtle.verify('HMAC', key, signature, data);
    
    if (!valid) return false;
    
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
    if (payload.exp <= Math.floor(Date.now() / 1000)) return false;
    
    return payload;
  } catch (_) {
    return false;
  }
}

// Extract Subject from raw email headers (fallback)
function extractSubject(raw: string): string {
  if (!raw) return '';
  const idx = raw.indexOf('\r\n\r\n');
  const idx2 = idx === -1 ? raw.indexOf('\n\n') : idx;
  const sep = idx !== -1 ? idx : (idx2 !== -1 ? idx2 : -1);
  const headerBlock = sep === -1 ? raw : raw.slice(0, sep);
  const lines = headerBlock.split(/\r?\n/);
  let lastKey = '';
  const headers: Record<string, string> = {};
  for (const line of lines) {
    if (/^\s/.test(line) && lastKey) {
      headers[lastKey] += ' ' + line.trim();
      continue;
    }
    const m = line.match(/^([^:]+):\s*(.*)$/);
    if (m) {
      lastKey = m[1].toLowerCase();
      headers[lastKey] = m[2];
    }
  }
  return headers['subject'] || '';
}

// Error response helper
function errorResponse(message: string, status: number = 400): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }
  });
}

// Success response helper
function jsonResponse(data: any, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method;
    const pathname = url.pathname;
    
    // Admin portal (HTML, cookie session; no CORS)
    if (pathname === '/admin' || pathname.startsWith('/admin/')) {
      try {
        await ensureSchema(env.TEMP_MAIL_DB);
        return await handleAdmin(request, env);
      } catch (error) {
        console.error('Admin error:', error);
        return new Response('Internal Server Error', { status: 500, headers: { 'Cache-Control': 'no-store' } });
      }
    }
    
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    
    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }
    
    try {
      // Public endpoints
      if (method === 'GET' && pathname === '/domains') {
        return await handleGetDomains(env);
      }

      // Everything below uses D1. The schema is checked once per isolate
      // (see database.js), not on every request.
      await ensureSchema(env.TEMP_MAIL_DB);
      
      if (method === 'POST' && pathname === '/accounts') {
        return await handleCreateAccount(request, env);
      }
      
      if (method === 'POST' && pathname === '/token') {
        return await handleCreateToken(request, env);
      }
      
      // Protected endpoints - require Bearer token
      const authHeader = request.headers.get('Authorization');
      const jwtSecret = jwtSecretOf(env);
      if (!jwtSecret) {
        console.error('JWT_SECRET is missing or shorter than 32 characters; refusing all tokens.');
        return errorResponse('Service not configured', 503);
      }
      const payload = await verifyBearerToken(authHeader, jwtSecret);
      
      if (!payload) {
        return errorResponse('Unauthorized', 401);
      }

      // Re-check the token against the database on every request, so deleted
      // or blocked users (e.g. public-created private-domain logins) lose access
      // even with a token issued earlier.
      if (!(await tokenStillValid(env, payload))) {
        return errorResponse('Unauthorized', 401);
      }
      
      if (method === 'GET' && pathname === '/me') {
        return await handleGetMe(payload, env);
      }
      
      if (method === 'GET' && pathname === '/messages') {
        return await handleGetMessages(url, payload, env);
      }
      
      const messageMatch = pathname.match(/^\/messages\/(.+)$/);
      if (messageMatch) {
        const messageId = messageMatch[1];
        
        if (method === 'GET') {
          return await handleGetMessage(messageId, payload, env);
        }
        
        if (method === 'PATCH') {
          return await handlePatchMessage(request, messageId, payload, env);
        }
        
        if (method === 'DELETE') {
          return await handleDeleteMessage(messageId, payload, env);
        }
      }
      
      return errorResponse('Not Found', 404);
      
    } catch (error) {
      console.error('Error:', error);
      return errorResponse('Internal Server Error', 500);
    }
  },
  
  // Email event handler for Cloudflare Email Routing
  async email(message: EmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    await ensureSchema(env.TEMP_MAIL_DB);
    const toAddress = (message as any).to?.toLowerCase?.() || String((message as any).to || '').toLowerCase();
    
    try {
      const mailboxId = await getOrCreateMailboxId(env.TEMP_MAIL_DB, toAddress);
      
      // Parse email content
      const rawObj: any = (message as any).raw;
      const rawEmail = typeof rawObj === 'string' ? rawObj : await new Response(rawObj).text();
      const parsedBody = parseEmailBody(rawEmail);
      const headers: Headers | undefined = (message as any).headers;
      const subjectHeader = headers && typeof headers.get === 'function' ? (headers.get('subject') || '') : '';
      const subject = subjectHeader || extractSubject(rawEmail) || '(No Subject)';
      
      // Insert message into database
      await env.TEMP_MAIL_DB.prepare(
        `INSERT INTO messages (mailbox_id, sender, subject, content, html_content, received_at) 
         VALUES (?, ?, ?, ?, ?, datetime('now'))`
      )
        .bind(
          mailboxId,
          (message as any).from,
          subject,
          parsedBody.text || '',
          parsedBody.html || null
        )
        .run();
        
    } catch (error) {
      console.error('Email processing error:', error);
    }

    // Optional forwarding (FORWARD_RULES). Runs after the copy is stored, and a
    // failed forward never affects the stored copy.
    const target = forwardTarget(env, toAddress);
    if (target) {
      try {
        await (message as any).forward(target);
      } catch (error) {
        console.error('Forward error:', error);
      }
    }
  }
};

// API Handlers

async function handleGetDomains(env: Env): Promise<Response> {
  // Only public domains; PRIVATE_DOMAINS are never listed.
  const domains = publicDomains(env);
  
  const hydraMembers = domains.map(domain => ({
    id: domain,
    domain: domain,
    isActive: true,
    isPrivate: false
  }));
  
  return jsonResponse({
    'hydra:member': hydraMembers,
    'hydra:totalItems': hydraMembers.length
  });
}

async function readJson(request: Request): Promise<any> {
  try {
    const body = await request.json();
    return body && typeof body === 'object' ? body : {};
  } catch (_) {
    return {};
  }
}

// Mail.tm style "already used" answer.
function addressAlreadyUsed(): Response {
  return jsonResponse({
    '@context': '/contexts/ConstraintViolationList',
    '@type': 'ConstraintViolationList',
    'hydra:title': 'An error occurred',
    'hydra:description': 'address: This value is already used.',
    violations: [{ propertyPath: 'address', message: 'This value is already used.' }],
    error: 'This value is already used.',
  }, 422);
}

async function handleCreateAccount(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const { address, password } = body;
  
  if (!address || !password || typeof address !== 'string' || typeof password !== 'string') {
    return errorResponse('Address and password are required');
  }
  
  // Validate domain
  const parts = splitAddress(address);
  if (!parts) {
    return errorResponse('Invalid domain');
  }
  const normalized = `${parts.local}@${parts.domain}`;

  if (isPrivateAddress(env, normalized)) {
    return errorResponse('This domain is private', 403);
  }
  if (!publicDomains(env).includes(parts.domain)) {
    return errorResponse('Invalid domain');
  }
  
  // An address that already has a login is never reset or taken over.
  if (await findUserByAddress(env.TEMP_MAIL_DB, address)) {
    return addressAlreadyUsed();
  }
  
  // Get or create mailbox
  const mailboxId = await getOrCreateMailboxId(env.TEMP_MAIL_DB, normalized);
  
  // Salted PBKDF2 (legacy SHA-256 hashes are still accepted at /token)
  const passwordHash = await hashPassword(password, USER_PBKDF2_ITERATIONS);
  
  try {
    await env.TEMP_MAIL_DB.prepare(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
    ).bind(normalized, passwordHash, 'user').run();
  } catch (error) {
    // UNIQUE(username): a concurrent request created it first.
    if (/unique/i.test(String((error as any)?.message || error))) {
      return addressAlreadyUsed();
    }
    throw error;
  }
  
  // Return account object
  const now = new Date().toISOString();
  return jsonResponse({
    id: String(mailboxId),
    address: address,
    quota: 0,
    used: 0,
    isDisabled: false,
    isDeleted: false,
    createdAt: now,
    updatedAt: now
  });
}

async function handleCreateToken(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const { address, password } = body;
  
  if (!address || !password || typeof address !== 'string' || typeof password !== 'string') {
    return errorResponse('Address and password are required');
  }

  const jwtSecret = jwtSecretOf(env);
  if (!jwtSecret) {
    console.error('JWT_SECRET is missing or shorter than 32 characters; refusing to issue tokens.');
    return errorResponse('Service not configured', 503);
  }

  // Failure limits (D1): per client+address, and per client overall. The
  // client is the browser's IP when the web app's proxy vouches for it
  // (signed header), else CF-Connecting-IP; IPv6 counts per /64.
  const ip = rateKeyForIp(await limitClientIp(request, env));
  const rules = [
    { key: `token:${ip}:${normalizeAddress(address)}`, limit: TOKEN_FAILURES_PER_IP_AND_ADDRESS },
    { key: `token:${ip}`, limit: TOKEN_FAILURES_PER_IP },
  ];
  // The attempt is counted before the password is checked (atomic), so
  // parallel requests cannot exceed the limits.
  const wait = await takeAttempt(env.TEMP_MAIL_DB, rules);
  if (wait > 0) {
    const res = errorResponse('Too many failed login attempts. Try again later.', 429);
    res.headers.set('Retry-After', String(wait));
    return res;
  }
  
  // Get user auth record
  const user = await findUserByAddress(env.TEMP_MAIL_DB, address);
  
  // Verify password; private-domain addresses need an admin-created login.
  const ok = !!user
    && password.length <= 1024
    && (await verifyPassword(password, user.password_hash))
    && userMayUseAddress(env, user, address)
    && userMayUseAddress(env, user, user.username);
  if (!user || !ok) {
    // The attempt taken above stays counted as a failure.
    return errorResponse('Invalid credentials', 401);
  }
  // Success: not a failure. Clears this address's counter, refunds the per-client one.
  await settleSuccess(env.TEMP_MAIL_DB, rules, [rules[0].key]);

  // Upgrade a legacy unsalted SHA-256 hash now that the password is known.
  if (isLegacyHash(user.password_hash)) {
    await env.TEMP_MAIL_DB.prepare(
      'UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?'
    ).bind(await hashPassword(password, USER_PBKDF2_ITERATIONS), user.id, user.password_hash).run();
  }
  
  // Get mailbox ID
  const mailboxId = await getMailboxIdByAddress(env.TEMP_MAIL_DB, user.username);
  if (!mailboxId) {
    return errorResponse('Mailbox not found', 404);
  }
  
  // Create JWT
  const token = await createJwt(jwtSecret, {
    address,
    mailboxId,
    userId: user.id
  });
  
  return jsonResponse({
    token,
    id: String(mailboxId)
  });
}

async function handleGetMe(payload: any, env: Env): Promise<Response> {
  const { address, mailboxId } = payload;
  const now = new Date().toISOString();
  
  return jsonResponse({
    id: String(mailboxId),
    address: address,
    quota: 0,
    used: 0,
    isDisabled: false,
    isDeleted: false,
    createdAt: now,
    updatedAt: now
  });
}

async function handleGetMessages(url: URL, payload: any, env: Env): Promise<Response> {
  const { mailboxId, address } = payload;
  // page=abc (NaN) or a huge page (not an integer OFFSET) used to reach D1 and
  // answer 500. Anything that is not a page number >= 1 is page 1 (0 and
  // negatives already acted as page 1); pages stop at 1,000,000.
  const page = Math.min(1_000_000, Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1));
  const limit = 30;
  const offset = (page - 1) * limit;
  
  // Get messages, newest first (idx_messages_mailbox_received: reads only
  // the rows up to this page; id breaks ties within the same second)
  const messages = await env.TEMP_MAIL_DB.prepare(
    `SELECT id, sender, subject, content, html_content, received_at, is_read 
     FROM messages 
     WHERE mailbox_id = ? 
     ORDER BY received_at DESC, id DESC 
     LIMIT ? OFFSET ?`
  ).bind(mailboxId, limit, offset).all();
  const pageRows = (messages.results || []).length;

  // Total count. A page that is not full ends the list, so the total is
  // known without counting (the usual case for an inbox that is polled).
  // A full or empty later page needs the COUNT, which reads one index row
  // per message of this mailbox.
  let totalCount: number;
  if (pageRows < limit && (pageRows > 0 || offset === 0)) {
    totalCount = offset + pageRows;
  } else {
    const countResult = await env.TEMP_MAIL_DB.prepare(
      'SELECT COUNT(*) as count FROM messages WHERE mailbox_id = ?'
    ).bind(mailboxId).first();
    totalCount = Number(countResult?.count || 0);
  }
  
  const hydraMembers = (messages.results || []).map(msg => {
    // Extract intro from content
    const textContent = String((msg as any).content || (msg as any).html_content || '');
    const intro = textContent.substring(0, 120);
    
    return {
      id: String((msg as any).id),
      from: {
        name: '',
        address: (msg as any).sender
      },
      to: [{
        name: '',
        address: address
      }],
      subject: (msg as any).subject,
      intro: intro,
      seen: (msg as any).is_read === 1,
      hasAttachments: false,
      size: textContent.length,
      downloadUrl: null,
      createdAt: (msg as any).received_at
    };
  });
  
  return jsonResponse({
    'hydra:member': hydraMembers,
    'hydra:totalItems': totalCount
  });
}

async function handleGetMessage(messageId: string, payload: any, env: Env): Promise<Response> {
  const { mailboxId, address } = payload;
  
  const message = await env.TEMP_MAIL_DB.prepare(
    `SELECT id, sender, subject, content, html_content, received_at, is_read 
     FROM messages 
     WHERE id = ? AND mailbox_id = ?`
  ).bind(messageId, mailboxId).first();
  
  if (!message) {
    return errorResponse('Message not found', 404);
  }
  
  // Return MessageDetail format
  return jsonResponse({
    id: String((message as any).id),
    from: {
      name: '',
      address: (message as any).sender
    },
    to: [{
      name: '',
      address: address
    }],
    subject: (message as any).subject,
    text: (message as any).content ? [(message as any).content] : [],
    html: (message as any).html_content ? [(message as any).html_content] : [],
    cc: [],
    bcc: [],
    createdAt: (message as any).received_at
  });
}

async function handlePatchMessage(request: Request, messageId: string, payload: any, env: Env): Promise<Response> {
  const { mailboxId } = payload;
  const body = await readJson(request);
  
  if ('seen' in body) {
    await env.TEMP_MAIL_DB.prepare(
      'UPDATE messages SET is_read = ? WHERE id = ? AND mailbox_id = ?'
    ).bind(body.seen ? 1 : 0, messageId, mailboxId).run();
    
    return jsonResponse({ seen: body.seen });
  }
  
  return errorResponse('Invalid update');
}

async function handleDeleteMessage(messageId: string, payload: any, env: Env): Promise<Response> {
  const { mailboxId } = payload;
  
  await env.TEMP_MAIL_DB.prepare(
    'DELETE FROM messages WHERE id = ? AND mailbox_id = ?'
  ).bind(messageId, mailboxId).run();
  
  return new Response(null, { 
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }
  });
} 