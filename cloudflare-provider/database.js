import { ensureAuthFailuresTable } from './security';

// Schema setup.
//
// D1 bills every row a statement reads, so nothing here may scan a data table
// on the request path. The Worker calls ensureSchema() before using D1: it
// checks the schema once per isolate (one lookup of SCHEMA_MARKER in
// sqlite_master, ~20 rows) and runs the full, idempotent migrateSchema() only
// when that marker is missing. (Until September 2026 the whole setup ran on
// every request, including a COUNT over all of messages: ~7,500 rows read per
// request.)

/**
 * The last object migrateSchema() creates: when it exists, every earlier
 * step has run. Give it a new name when adding a migration step.
 */
export const SCHEMA_MARKER = 'idx_auth_failures_window_start';

// Only a flag is kept per isolate (plain data, never a promise or other I/O
// object shared across requests). Requests that arrive while the first
// check is still running do the same cheap check themselves.
let schemaReady = false;

/** Makes sure the schema is current, at most once per isolate. Never throws. */
export async function ensureSchema(db) {
  if (schemaReady) return;
  try {
    const marker = await db.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'index' AND name = ?")
      .bind(SCHEMA_MARKER).first();
    if (!marker) await migrateSchema(db);
    schemaReady = true;
  } catch (error) {
    // As before, a failed setup does not fail the request; the next request tries again.
    console.error('Schema setup failed:', error);
  }
}

/** Tests only: the next ensureSchema() checks again (after the test wiped the database). */
export function forgetSchemaCheck() {
  schemaReady = false;
}

/** Runs the full migration now (errors are logged, not thrown). */
export async function initDatabase(db) {
  try {
    await migrateSchema(db);
  } catch (error) {
    console.error('数据库初始化失败:', error);
  }
}

/** Creates and upgrades every table and index. Idempotent; throws on failure. */
export async function migrateSchema(db) {
  await db.exec(`PRAGMA foreign_keys = ON;`);

  // 新结构：mailboxes（地址历史） + messages（邮件）
  await db.exec("CREATE TABLE IF NOT EXISTS mailboxes (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE, local_part TEXT NOT NULL, domain TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_accessed_at TEXT, expires_at TEXT, is_pinned INTEGER DEFAULT 0);");
  // 迁移：为现有邮箱添加 is_pinned 字段 (before its index, which needs the column)
  try {
    const res = await db.prepare("PRAGMA table_info(mailboxes)").all();
    const cols = (res?.results || []).map(r => (r.name || r?.['name']));
    if (!cols.includes('is_pinned')){
      await db.exec('ALTER TABLE mailboxes ADD COLUMN is_pinned INTEGER DEFAULT 0');
    }
  } catch (error) {
    console.warn('Migration warning (is_pinned column may already exist):', error.message);
  }
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_mailboxes_address ON mailboxes(address);`);
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_mailboxes_is_pinned ON mailboxes(is_pinned DESC);`);

  await db.exec("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, mailbox_id INTEGER NOT NULL, sender TEXT NOT NULL, subject TEXT NOT NULL, content TEXT NOT NULL, html_content TEXT, received_at TEXT DEFAULT CURRENT_TIMESTAMP, is_read INTEGER DEFAULT 0, FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id));");
  // One mailbox's messages, newest first: GET /messages pages, COUNT per
  // mailbox, and MAX(received_at) per mailbox (one index row) on /admin.
  // It replaces idx_messages_mailbox_id (its prefix), so a new message still
  // writes the same number of index rows.
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_mailbox_received ON messages(mailbox_id, received_at);`);
  await db.exec(`DROP INDEX IF EXISTS idx_messages_mailbox_id;`);
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at DESC);`);

  // 用户与授权关系表
  await ensureUsersTables(db);

  // 发送记录表：用于记录通过 Resend 发出的邮件与状态
  await ensureSentEmailsTable(db);

  await migrateLegacyEmails(db);

  // Failure counters for /token and /admin/login (security.ts). The index
  // keeps the expired-row cleanup an index range instead of a table scan.
  await ensureAuthFailuresTable(db);
  // Keep this the last statement: it is SCHEMA_MARKER.
  await db.exec(`CREATE INDEX IF NOT EXISTS ${SCHEMA_MARKER} ON auth_failures(window_start);`);
}

/**
 * 兼容迁移：若存在旧表 emails 且新表 messages 为空，则迁移数据。
 * The table is looked up by name first; messages is only probed for one row
 * (never counted) and only on installs that still have the old table.
 */
async function migrateLegacyEmails(db) {
  const legacy = await db.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'emails'").first();
  if (!legacy) return;
  const hasMessages = await db.prepare('SELECT 1 AS ok FROM messages LIMIT 1').first();
  if (hasMessages) return;
  const res = await db.prepare('SELECT * FROM emails').all();
  const rows = res?.results || [];
  for (const r of rows) {
    const mailboxId = await getOrCreateMailboxId(db, r.mailbox);
    await db.prepare(`INSERT INTO messages (mailbox_id, sender, subject, content, html_content, received_at, is_read)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(mailboxId, r.sender, r.subject, r.content, r.html_content || null, r.received_at || null, r.is_read || 0)
      .run();
  }
}

export async function getOrCreateMailboxId(db, address) {
  const normalized = String(address || '').trim().toLowerCase();
  if (!normalized) throw new Error('无效的邮箱地址');
  let local_part = '';
  let domain = '';
  const at = normalized.indexOf('@');
  if (at > 0 && at < normalized.length - 1) {
    local_part = normalized.slice(0, at);
    domain = normalized.slice(at + 1);
  }
  if (!local_part || !domain) throw new Error('无效的邮箱地址');
  const existing = await db.prepare('SELECT id FROM mailboxes WHERE address = ?').bind(normalized).all();
  if (existing.results && existing.results.length > 0) {
    const id = existing.results[0].id;
    await db.prepare('UPDATE mailboxes SET last_accessed_at = CURRENT_TIMESTAMP WHERE id = ?').bind(id).run();
    return id;
  }
  const res = await db.prepare(
    'INSERT INTO mailboxes (address, local_part, domain, last_accessed_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)'
  ).bind(normalized, local_part, domain).run();
  // D1 返回对象不一定带 last_insert_rowid，可再查一次
  const created = await db.prepare('SELECT id FROM mailboxes WHERE address = ?').bind(normalized).all();
  return created.results[0].id;
}

export async function getMailboxIdByAddress(db, address) {
  const normalized = String(address || '').trim().toLowerCase();
  if (!normalized) return null;
  const res = await db.prepare('SELECT id FROM mailboxes WHERE address = ?').bind(normalized).all();
  return (res.results && res.results.length) ? res.results[0].id : null;
}

export async function toggleMailboxPin(db, address, userId) {
  const normalized = String(address || '').trim().toLowerCase();
  if (!normalized) throw new Error('无效的邮箱地址');
  const uid = Number(userId || 0);
  if (!uid) throw new Error('未登录');

  // 获取邮箱 ID
  const mbRes = await db.prepare('SELECT id FROM mailboxes WHERE address = ?').bind(normalized).all();
  if (!mbRes.results || mbRes.results.length === 0){
    throw new Error('邮箱不存在');
  }
  const mailboxId = mbRes.results[0].id;

  // 检查该邮箱是否属于该用户
  const umRes = await db.prepare('SELECT id, is_pinned FROM user_mailboxes WHERE user_id = ? AND mailbox_id = ?')
    .bind(uid, mailboxId).all();
  if (!umRes.results || umRes.results.length === 0){
    // 若尚未存在关联记录（例如严格管理员未分配该邮箱），则创建一条仅用于个人置顶的关联
    await db.prepare('INSERT INTO user_mailboxes (user_id, mailbox_id, is_pinned) VALUES (?, ?, 1)')
      .bind(uid, mailboxId).run();
    return { is_pinned: 1 };
  }

  const currentPin = umRes.results[0].is_pinned ? 1 : 0;
  const newPin = currentPin ? 0 : 1;
  await db.prepare('UPDATE user_mailboxes SET is_pinned = ? WHERE user_id = ? AND mailbox_id = ?')
    .bind(newPin, uid, mailboxId).run();
  return { is_pinned: newPin };
}

export async function recordSentEmail(db, { resendId, fromName, from, to, subject, html, text, status = 'queued', scheduledAt = null }){
  const toAddrs = Array.isArray(to) ? to.join(',') : String(to || '');
  try{
    await db.prepare(`
      INSERT INTO sent_emails (resend_id, from_name, from_addr, to_addrs, subject, html_content, text_content, status, scheduled_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(resendId || null, fromName || null, from, toAddrs, subject, html || null, text || null, status, scheduledAt || null).run();
  } catch (e) {
    // 如果表不存在，尝试即时创建并重试一次
    if ((e?.message || '').toLowerCase().includes('no such table: sent_emails')){
      try { await ensureSentEmailsTable(db); } catch(_){}
      await db.prepare(`
        INSERT INTO sent_emails (resend_id, from_name, from_addr, to_addrs, subject, html_content, text_content, status, scheduled_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(resendId || null, fromName || null, from, toAddrs, subject, html || null, text || null, status, scheduledAt || null).run();
      return;
    }
    throw e;
  }
}

export async function updateSentEmail(db, resendId, fields){
  if (!resendId) return;
  const allowed = ['status', 'scheduled_at'];
  const setClauses = [];
  const values = [];
  for (const key of allowed){
    if (key in (fields || {})){
      setClauses.push(`${key} = ?`);
      values.push(fields[key]);
    }
  }
  if (!setClauses.length) return;
  setClauses.push('updated_at = CURRENT_TIMESTAMP');
  const sql = `UPDATE sent_emails SET ${setClauses.join(', ')} WHERE resend_id = ?`;
  values.push(resendId);
  await db.prepare(sql).bind(...values).run();
}

export async function ensureSentEmailsTable(db){
  await db.exec(
    'CREATE TABLE IF NOT EXISTS sent_emails (' +
    'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    'resend_id TEXT,' +
    'from_name TEXT,' +
    'from_addr TEXT NOT NULL,' +
    'to_addrs TEXT NOT NULL,' +
    'subject TEXT NOT NULL,' +
    'html_content TEXT,' +
    'text_content TEXT,' +
    "status TEXT DEFAULT 'queued'," +
    'scheduled_at TEXT,' +
    'created_at TEXT DEFAULT CURRENT_TIMESTAMP,' +
    'updated_at TEXT DEFAULT CURRENT_TIMESTAMP' +
    ')'
  );
  try {
    const res = await db.prepare("PRAGMA table_info(sent_emails)").all();
    const cols = (res?.results || []).map(r => (r.name || r?.['name']));
    if (!cols.includes('from_name')) {
      await db.exec('ALTER TABLE sent_emails ADD COLUMN from_name TEXT');
    }
  } catch (_) {}
}

// ============== 用户与授权相关 ==============
export async function ensureUsersTables(db){
  await db.exec(
    "CREATE TABLE IF NOT EXISTS users (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "username TEXT NOT NULL UNIQUE," +
    "password_hash TEXT," +
    "role TEXT NOT NULL DEFAULT 'user'," +
    "can_send INTEGER NOT NULL DEFAULT 0," +
    "mailbox_limit INTEGER NOT NULL DEFAULT 10" +
    ")"
  );
  try {
    const res = await db.prepare("PRAGMA table_info(users)").all();
    const cols = (res?.results || []).map(r => (r.name || r?.['name']));
    if (!cols.includes('can_send')) {
      await db.exec('ALTER TABLE users ADD COLUMN can_send INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.includes('mailbox_limit')) {
      await db.exec('ALTER TABLE users ADD COLUMN mailbox_limit INTEGER NOT NULL DEFAULT 10');
    }
  } catch (_) {}
  // Logins are looked up by lower(trim(username)) (older rows kept the address
  // as typed); this expression index keeps that lookup an index seek.
  await db.exec('CREATE INDEX IF NOT EXISTS idx_users_username_norm ON users(lower(trim(username)))');

  await db.exec(
    "CREATE TABLE IF NOT EXISTS user_mailboxes (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "user_id INTEGER NOT NULL," +
    "mailbox_id INTEGER NOT NULL," +
    "created_at TEXT DEFAULT CURRENT_TIMESTAMP," +
    "is_pinned INTEGER NOT NULL DEFAULT 0" +
    ")"
  );
  try {
    const um = await db.prepare("PRAGMA table_info(user_mailboxes)").all();
    const cols = (um?.results || []).map(r => (r.name || r?.['name']));
    if (!cols.includes('is_pinned')) {
      await db.exec('ALTER TABLE user_mailboxes ADD COLUMN is_pinned INTEGER NOT NULL DEFAULT 0');
    }
  } catch (_) {}
}

export async function createUser(db, { username, passwordHash = null, role = 'user', mailboxLimit = 10 }){
  const uname = String(username || '').trim().toLowerCase();
  if (!uname) throw new Error('用户名不能为空');
  const r = await db.prepare('INSERT INTO users (username, password_hash, role, mailbox_limit) VALUES (?, ?, ?, ?)')
    .bind(uname, passwordHash, role, Math.max(0, Number(mailboxLimit || 10))).run();
  const res = await db.prepare('SELECT id, username, role, mailbox_limit, created_at FROM users WHERE username = ?')
    .bind(uname).all();
  return res?.results?.[0];
}

export async function updateUser(db, userId, fields){
  const allowed = ['role', 'mailbox_limit', 'password_hash', 'can_send'];
  const setClauses = [];
  const values = [];
  for (const key of allowed){
    if (key in (fields || {})){
      setClauses.push(`${key} = ?`);
      values.push(fields[key]);
    }
  }
  if (!setClauses.length) return;
  const sql = `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`;
  values.push(userId);
  await db.prepare(sql).bind(...values).run();
}

export async function deleteUser(db, userId){
  // 关联表启用 ON DELETE CASCADE
  await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
}

export async function listUsersWithCounts(db, { limit = 50, offset = 0 } = {}){
  const sql = `
    SELECT u.id, u.username, u.role, u.mailbox_limit, u.can_send, u.created_at,
           COALESCE(cnt.c, 0) AS mailbox_count
    FROM users u
    LEFT JOIN (
      SELECT user_id, COUNT(1) AS c FROM user_mailboxes GROUP BY user_id
    ) cnt ON cnt.user_id = u.id
    ORDER BY datetime(u.created_at) DESC
    LIMIT ? OFFSET ?
  `;
  const { results } = await db.prepare(sql).bind(Math.max(1, Math.min(100, Number(limit) || 50)), Math.max(0, Number(offset) || 0)).all();
  return results || [];
}

export async function assignMailboxToUser(db, { userId = null, username = null, address }){
  const normalized = String(address || '').trim().toLowerCase();
  if (!normalized) throw new Error('邮箱地址无效');
  // 查询或创建邮箱
  const mailboxId = await getOrCreateMailboxId(db, normalized);

  // 获取用户 ID
  let uid = userId;
  if (!uid){
    const uname = String(username || '').trim().toLowerCase();
    if (!uname) throw new Error('缺少用户标识');
    const r = await db.prepare('SELECT id FROM users WHERE username = ?').bind(uname).all();
    if (!r.results || !r.results.length) throw new Error('用户不存在');
    uid = r.results[0].id;
  }

  // 校验上限
  const ures = await db.prepare('SELECT mailbox_limit FROM users WHERE id = ?').bind(uid).all();
  const limit = ures?.results?.[0]?.mailbox_limit ?? 10;
  const cres = await db.prepare('SELECT COUNT(1) AS c FROM user_mailboxes WHERE user_id = ?').bind(uid).all();
  const count = cres?.results?.[0]?.c || 0;
  if (count >= limit) throw new Error('已达到邮箱上限');

  // 绑定（唯一约束避免重复）
  await db.prepare('INSERT OR IGNORE INTO user_mailboxes (user_id, mailbox_id) VALUES (?, ?)').bind(uid, mailboxId).run();
  return { success: true };
}

export async function getUserMailboxes(db, userId){
  const sql = `
    SELECT m.address, m.created_at, um.is_pinned
    FROM user_mailboxes um
    JOIN mailboxes m ON m.id = um.mailbox_id
    WHERE um.user_id = ?
    ORDER BY um.is_pinned DESC, datetime(m.created_at) DESC
  `;
  const { results } = await db.prepare(sql).bind(userId).all();
  return results || [];
}

