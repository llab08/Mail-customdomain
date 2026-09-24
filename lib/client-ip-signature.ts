// Server-only helper for app/api/mail/route.ts.
//
// The Cloudflare Worker limits failed logins per client IP. Every web-app
// request reaches the Worker from this server, so without help the Worker
// would see one IP for all users and anyone could lock everyone out. The
// proxy therefore passes the browser's IP in X-DuckMail-Client-IP with an
// HMAC signature the Worker checks (cloudflare-provider/security.ts,
// limitClientIp). The shared secret is CLIENT_IP_SECRET: set the same value
// here (server env var, never NEXT_PUBLIC_) and as the Worker secret.
//
// The signature binds the IP and a timestamp, so a captured header only ever
// speaks for the IP it was made for, and only for a few minutes.
import { createHmac } from "node:crypto"

export const CLIENT_IP_HEADER = "X-DuckMail-Client-IP"
export const CLIENT_IP_SIGNATURE_HEADER = "X-DuckMail-Client-IP-Signature"
const MIN_SECRET_LENGTH = 32

/** "v1.<unix seconds>.<base64url HMAC-SHA256(secret, 'v1.<ts>.<ip>')>" (same as the Worker). */
export function signClientIp(secret: string, ip: string, ts: number): string {
  const mac = createHmac("sha256", secret).update(`v1.${ts}.${ip}`).digest("base64url")
  return `v1.${ts}.${mac}`
}

/**
 * The browser's IP as the hosting platform reports it. On Vercel (and
 * Netlify) the platform sets these headers itself and overwrites any value
 * the client sent; do not deploy this proxy behind a host that passes a
 * client-supplied X-Forwarded-For through unchanged.
 */
export function browserIp(headers: Headers): string | null {
  const candidates = [
    headers.get("x-real-ip"),
    headers.get("x-nf-client-connection-ip"),
    (headers.get("x-forwarded-for") || "").split(",")[0],
  ]
  for (const c of candidates) {
    const ip = (c || "").trim()
    if (ip && ip.length <= 64 && /^[0-9A-Fa-f:.]+$/.test(ip)) return ip
  }
  return null
}

/** Origin of the Worker this app is configured for; only it receives the signed header. */
function workerOrigin(): string | null {
  const base = (process.env.NEXT_PUBLIC_CLOUDFLARE_WORKER_BASE_URL || "").trim()
  if (!base) return null
  try {
    return new URL(base).origin
  } catch {
    return null
  }
}

/**
 * Adds the signed client-IP headers when CLIENT_IP_SECRET is set, the target
 * is the configured Worker (never a base URL the browser chose through
 * X-API-Provider-Base-URL), and the platform reported the browser's IP.
 */
export function addClientIpHeaders(target: string, incoming: Headers, outgoing: Headers, now: number = Date.now()): void {
  outgoing.delete(CLIENT_IP_HEADER)
  outgoing.delete(CLIENT_IP_SIGNATURE_HEADER)
  const secret = process.env.CLIENT_IP_SECRET || ""
  if (secret.length < MIN_SECRET_LENGTH) return
  const origin = workerOrigin()
  let targetOrigin: string
  try {
    targetOrigin = new URL(target).origin
  } catch {
    return
  }
  if (!origin || targetOrigin !== origin) return
  const ip = browserIp(incoming)
  if (!ip) return
  outgoing.set(CLIENT_IP_HEADER, ip)
  outgoing.set(CLIENT_IP_SIGNATURE_HEADER, signClientIp(secret, ip, Math.floor(now / 1000)))
}
