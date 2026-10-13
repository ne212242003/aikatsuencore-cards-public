// 枚数の同期API（Cloudflare Pages Functions + D1）
// 置き場所: リポジトリの functions/api/sync.js  →  https://サイト名/api/sync
// D1のバインド変数名は「DB」にしてください。
//
// 保存するもの: カードのid・枚数・「欲しい」の印・最後に変えた時刻 だけ（名前やメールアドレスなどは保存しません）
// 専用の番号（キー）は、そのままでは保存せず、ハッシュ（元に戻せない形）にして保存します。

const KEY_RE = /^[A-Za-z0-9_-]{22,64}$/;
const ID_RE = /^[A-Za-z0-9_.-]{1,40}$/;
const MAX_ENTRIES = 3000;       // 1人分のカード数の上限
const MAX_BYTES = 120000;       // 送られてくるデータの大きさの上限
const MIN_WRITE_GAP_MS = 1000;  // 同じ番号で、続けて保存できる間隔
const MAX_NEW_PER_IP_PER_DAY = 30; // 1つの回線から、1日に新しく作れる数
const KEEP_DAYS = 365;          // これだけ使われなかったデータは、自動で消します

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// 送られてきたデータを検査して、{id: [枚数, 欲しい(0/1), 時刻]} の形にそろえる
function clean(data, now) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const ids = Object.keys(data);
  if (ids.length > MAX_ENTRIES) return null;
  const out = {};
  for (const id of ids) {
    if (!ID_RE.test(id)) return null;
    const v = data[id];
    if (!Array.isArray(v) || v.length < 3) return null;
    const q = Math.max(0, Math.min(99, Math.trunc(Number(v[0])) || 0));
    const w = v[1] ? 1 : 0;
    let t = Math.trunc(Number(v[2])) || 1;
    if (t < 1) t = 1;
    if (t > now + 86400000) t = now; // 未来の時刻は、いまに直す
    out[id] = [q, w, t];
  }
  return out;
}

// カードごとに、時刻が新しいほうを残す
function merge(a, b) {
  const out = { ...a };
  for (const id of Object.keys(b)) {
    const x = out[id];
    if (!x || b[id][2] >= x[2]) out[id] = b[id];
  }
  return out;
}

export async function onRequest(context) {
  const { request, env } = context;
  if (!env.DB) return json({ error: "db_not_configured" }, 503);

  const url = new URL(request.url);
  const k = url.searchParams.get("k") || "";
  if (!KEY_RE.test(k)) return json({ error: "bad_key" }, 400);
  const h = await sha256(k);
  const now = Date.now();

  if (request.method === "GET") {
    let row = await env.DB.prepare("SELECT data, updated_at FROM profiles WHERE key_hash = ?").bind(h).first();
    if (row) return json({ data: JSON.parse(row.data), updated: row.updated_at, ro: false });
    row = await env.DB.prepare("SELECT data, updated_at FROM profiles WHERE ro_hash = ?").bind(h).first();
    if (row) return json({ data: JSON.parse(row.data), updated: row.updated_at, ro: true });
    return json({ error: "not_found" }, 404);
  }

  if (request.method === "PUT") {
    const text = await request.text();
    if (text.length > MAX_BYTES) return json({ error: "too_large" }, 413);
    let body;
    try { body = JSON.parse(text); } catch (e) { return json({ error: "bad_json" }, 400); }
    const incoming = clean(body && body.data, now);
    if (!incoming) return json({ error: "bad_data" }, 400);

    let roHash = null;
    if (body.ro !== undefined && body.ro !== null) {
      if (typeof body.ro !== "string" || !KEY_RE.test(body.ro) || body.ro === k) return json({ error: "bad_ro" }, 400);
      roHash = await sha256(body.ro);
    }

    // 「見るだけのリンク」の番号では、書き込めません（新しく作ることもできません）
    const roRow = await env.DB.prepare("SELECT 1 AS x FROM profiles WHERE ro_hash = ?").bind(h).first();
    if (roRow) return json({ error: "read_only" }, 403);

    const row = await env.DB.prepare("SELECT data, updated_at FROM profiles WHERE key_hash = ?").bind(h).first();
    if (row) {
      if (now - row.updated_at < MIN_WRITE_GAP_MS) return json({ error: "too_fast" }, 429);
      const merged = merge(JSON.parse(row.data), incoming);
      try {
        await env.DB.prepare("UPDATE profiles SET data = ?, updated_at = ?, ro_hash = COALESCE(?, ro_hash) WHERE key_hash = ?")
          .bind(JSON.stringify(merged), now, roHash, h).run();
      } catch (e) { return json({ error: "conflict" }, 409); }
      if (Math.random() < 0.02 && context.waitUntil) context.waitUntil(cleanup(env, now));
      return json({ data: merged, updated: now });
    }

    // 新しく作るとき: 同じ回線から、1日に作れる数を制限する
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const day = new Date(now).toISOString().slice(0, 10);
    const ipHash = await sha256("ip:" + ip);
    const c = await env.DB.prepare("SELECT n FROM creates WHERE ip_hash = ? AND day = ?").bind(ipHash, day).first();
    if (c && c.n >= MAX_NEW_PER_IP_PER_DAY) return json({ error: "rate_limited" }, 429);
    await env.DB.prepare("INSERT INTO creates (ip_hash, day, n) VALUES (?, ?, 1) ON CONFLICT(ip_hash, day) DO UPDATE SET n = n + 1")
      .bind(ipHash, day).run();
    try {
      await env.DB.prepare("INSERT INTO profiles (key_hash, ro_hash, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
        .bind(h, roHash, JSON.stringify(incoming), now, now).run();
    } catch (e) { return json({ error: "conflict" }, 409); }
    return json({ data: incoming, updated: now });
  }

  if (request.method === "DELETE") {
    await env.DB.prepare("DELETE FROM profiles WHERE key_hash = ?").bind(h).run();
    return json({ ok: true });
  }

  return json({ error: "method_not_allowed" }, 405);
}

async function cleanup(env, now) {
  try {
    await env.DB.prepare("DELETE FROM profiles WHERE updated_at < ?").bind(now - KEEP_DAYS * 86400000).run();
    const oldDay = new Date(now - 3 * 86400000).toISOString().slice(0, 10);
    await env.DB.prepare("DELETE FROM creates WHERE day < ?").bind(oldDay).run();
  } catch (e) { /* 失敗しても、動作には影響しません */ }
}
