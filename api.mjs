// Super Mobile Shop – সার্ভার-সাইড API (Netlify Functions v2 + Netlify Blobs)
// রুট: GET /api/state · PUT /api/state · POST /api/login · POST /api/logout · GET /api/me
//      POST /api/upload · GET /api/img/:id
import { getStore } from "@netlify/blobs";
import { createHmac, createHash, timingSafeEqual, randomBytes, randomUUID } from "node:crypto";

export const config = { path: "/api/*" };

const env = (k) => (typeof Netlify !== "undefined" ? Netlify.env.get(k) : process.env[k]);
const J = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers },
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (s) => createHash("sha256").update(s).digest();
const safeEq = (a, b) => timingSafeEqual(sha(String(a)), sha(String(b)));

// ---------- সেশন (HMAC-সই করা, HttpOnly কুকি) ----------
const secret = () => {
  const s = env("SESSION_SECRET");
  if (!s || s.length < 32) throw new Error("SESSION_SECRET not configured");
  return s;
};
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return body + "." + createHmac("sha256", secret()).update(body).digest("base64url");
}
function verify(tok) {
  if (!tok || !tok.includes(".")) return null;
  const [body, sig] = tok.split(".");
  const exp = createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(exp);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
const getCookie = (req, name) => {
  for (const part of (req.headers.get("cookie") || "").split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return "";
};
const sessionOf = (req) => { try { return verify(getCookie(req, "sid")); } catch { return null; } };
const setCookie = (v, maxAge) => `sid=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;

// অ্যাডমিন যাচাই: বৈধ সেশন + (লেখার অনুরোধে) একই-অরিজিন + CSRF টোকেন
function adminOf(req) {
  const s = sessionOf(req);
  if (!s) return null;
  if (req.method !== "GET") {
    const origin = req.headers.get("origin");
    if (!origin) return null;
    try { if (new URL(origin).host !== new URL(req.url).host) return null; } catch { return null; }
    const t = Buffer.from(req.headers.get("x-csrf-token") || ""), c = Buffer.from(String(s.csrf));
    if (t.length !== c.length || !timingSafeEqual(t, c)) return null;
  }
  return s;
}

async function readJSON(req, max) {
  const text = await req.text();
  if (text.length > max) throw Object.assign(new Error("too large"), { status: 413 });
  try { return JSON.parse(text); } catch { throw Object.assign(new Error("bad json"), { status: 400 }); }
}

// ---------- ইনপুট স্যানিটাইজ (সার্ভারে, ক্লায়েন্টকে বিশ্বাস না করে) ----------
const T = (v, n = 200) => (typeof v === "string" ? v.replace(/[<>"'`\u0000-\u001f]/g, "").slice(0, n) : "");
const Nn = (v, lo = 0, hi = 1e9) => { const x = Number(v); return Number.isFinite(x) ? Math.min(hi, Math.max(lo, x)) : 0; };
const HEX = (v, d) => (typeof v === "string" && /^#[0-9a-fA-F]{6}$/.test(v) ? v : d);
const IMG = (u) => typeof u === "string" && (/^\/api\/img\/[0-9a-f-]{36}$/.test(u) || /^https:\/\/[^\s<>"'`]{1,500}$/.test(u));

function cleanPhone(p) {
  if (!p || typeof p !== "object" || !Number.isInteger(p.id) || p.id < 0 || p.id > 1e6) return null;
  const m = T(p.m, 80), price = Nn(p.p, 0, 1e8);
  if (!m || price <= 0) return null;
  const col = typeof p.col === "string" && (HEX(p.col, "") || IMG(p.col)) ? p.col : "#4b5563";
  const o = Nn(p.o, 0, 1e8);
  return {
    id: p.id, b: T(p.b, 40) || "অন্যান্য", m, c: p.c === "used" ? "used" : "new", g: T(p.g, 8) || "New",
    off: !!p.off, p: price, o: o > price ? o : 0, ram: Nn(p.ram, 0, 1024), rom: Nn(p.rom, 0, 16384),
    cpu: T(p.cpu, 80), gpu: T(p.gpu, 80), scr: T(p.scr, 80), cam: T(p.cam, 120), bat: T(p.bat, 80), os: T(p.os, 60),
    note: T(p.note, 600), r: Nn(p.r, 0, 5), n: Nn(p.n, 0, 1e6), col,
    imgs: Array.isArray(p.imgs) ? p.imgs.filter(IMG).slice(0, 8) : [],
  };
}
const obj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
function cleanSite(s) {
  s = obj(s);
  const o = {};
  for (const k of ["name", "tag", "ht", "hs", "brands", "ranges", "cl", "bh", "uh", "gt"]) if (k in s) o[k] = T(s[k], 400);
  for (const k of ["ar", "rad", "fs", "sh", "col", "lim", "deal"]) if (k in s) o[k] = String(T(String(s[k]), 120)).replace(/[^0-9a-zA-Z .,()%/#-]/g, "");
  for (const k of ["bg", "ac", "dbc"]) if (k in s) o[k] = HEX(s[k], "#ffffff");
  if (Array.isArray(s.hf)) o.hf = s.hf.map((x) => T(x, 12)).slice(0, 12);
  if (Array.isArray(s.order)) o.order = s.order.map((x) => T(x, 12)).slice(0, 12);
  if (Array.isArray(s.off)) o.off = s.off.map((x) => T(x, 12)).slice(0, 12);
  o.v = 2;
  return o;
}
function cleanOfr(s) {
  s = obj(s);
  const o = {};
  for (const k of ["t", "x", "btn"]) if (k in s) o[k] = T(s[k], 200);
  for (const k of ["on", "pop", "th"]) if (k in s) o[k] = T(String(s[k]), 12);
  if ("end" in s) o.end = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s.end) ? s.end : "";
  for (const k of ["c1", "c2", "ca"]) if (k in s) o[k] = HEX(s[k], "#0f172a");
  return o;
}
function cleanCfg(s) {
  s = obj(s);
  const o = {};
  if ("wa" in s) o.wa = String(s.wa).replace(/\D/g, "").slice(0, 20);
  if ("tel" in s) o.tel = String(s.tel).replace(/[^\d+ -]/g, "").slice(0, 24);
  if ("email" in s && /^[^\s@<>"']{1,64}@[^\s@<>"']{1,200}$/.test(s.email)) o.email = s.email;
  if ("addr" in s) o.addr = T(s.addr, 200);
  return o;
}
function cleanState(b) {
  b = obj(b);
  const extra = (Array.isArray(b.extra) ? b.extra : []).slice(0, 500).map(cleanPhone).filter(Boolean);
  const pst = {};
  for (const [k, v] of Object.entries(obj(b.pst)).slice(0, 2000)) {
    if (/^\d{1,7}$/.test(k)) pst[k] = { s: !!obj(v).s, h: !!obj(v).h };
  }
  return {
    extra,
    hide: (Array.isArray(b.hide) ? b.hide : []).filter((x) => Number.isInteger(x) && x >= 0 && x < 1e6).slice(0, 2000),
    pst, cfg: cleanCfg(b.cfg), site: cleanSite(b.site), ofr: cleanOfr(b.ofr), demo: b.demo === "0" ? "0" : "1",
  };
}

// ---------- রেট লিমিট (পাসওয়ার্ড ব্রুট-ফোর্স ঠেকাতে) ----------
async function failState(store, key) {
  return (await store.get(key, { type: "json" })) || { n: 0, t: 0, u: 0 };
}
const ipKey = (ip) => "rl/ip-" + sha(String(ip || "unknown")).toString("hex").slice(0, 24);

export default async (req, context) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  const method = req.method;
  try {
    if (path === "/api/health") return J({ ok: true });

    // --- জনসাধারণ: দোকানের তথ্য ---
    if (path === "/api/state" && method === "GET") {
      const store = getStore({ name: "shop", consistency: "strong" });
      const data = (await store.get("state", { type: "json" })) || {};
      const isAdmin = !!sessionOf(req);
      if (!isAdmin && Array.isArray(data.extra)) {
        const hidden = new Set(Object.entries(data.pst || {}).filter(([, v]) => v && v.h).map(([k]) => Number(k)));
        data.extra = data.extra.filter((p) => !hidden.has(p.id));
      }
      return J(data);
    }
    if (path === "/api/me" && method === "GET") {
      const s = sessionOf(req);
      return J({ admin: !!s, csrf: s ? s.csrf : "" });
    }
    if (path.startsWith("/api/img/") && method === "GET") {
      const id = path.slice(9);
      if (!/^[0-9a-f-]{36}$/.test(id)) return J({ error: "not found" }, 404);
      const r = await getStore("shop-images").getWithMetadata(id, { type: "arrayBuffer" });
      if (!r) return J({ error: "not found" }, 404);
      const type = ["image/jpeg", "image/png", "image/webp"].includes(r.metadata?.type) ? r.metadata.type : "application/octet-stream";
      return new Response(r.data, { headers: { "content-type": type, "x-content-type-options": "nosniff", "cache-control": "public, max-age=31536000, immutable", "content-security-policy": "default-src 'none'; sandbox" } });
    }

    // --- লগইন ---
    if (path === "/api/login" && method === "POST") {
      const want = env("ADMIN_PASSWORD") || "";
      if (want.length < 10) return J({ error: "অ্যাডমিন পাসওয়ার্ড সার্ভারে সেট করা নেই (কমপক্ষে ১০ অক্ষর)" }, 503);
      const store = getStore({ name: "shop", consistency: "strong" });
      const now = Date.now(), kIp = ipKey(context?.ip), kAll = "rl/global";
      const [ip, all] = [await failState(store, kIp), await failState(store, kAll)];
      if (ip.u > now) return J({ error: "locked", retry: Math.ceil((ip.u - now) / 1000) }, 429);
      if (all.u > now) return J({ error: "locked", retry: Math.ceil((all.u - now) / 1000) }, 429);
      const body = await readJSON(req, 2000);
      if (safeEq(String(body?.password || ""), want)) {
        await store.delete(kIp);
        const csrf = randomBytes(24).toString("base64url");
        const tok = sign({ exp: now + 2 * 3600e3, csrf });
        return J({ ok: true, csrf }, 200, { "set-cookie": setCookie(tok, 7200) });
      }
      await sleep(700); // ধীর করে দেওয়া
      const n = (now - ip.t > 15 * 60e3 ? 0 : ip.n) + 1;
      const u = n >= 5 ? now + Math.min(3600e3, 2 ** (n - 5) * 5 * 60e3) : 0;
      await store.setJSON(kIp, { n, t: now, u });
      const gn = (now - all.t > 3600e3 ? 0 : all.n) + 1;
      await store.setJSON(kAll, { n: gn, t: now, u: gn >= 40 ? now + 10 * 60e3 : 0 });
      return J({ error: "bad", retry: u ? Math.ceil((u - now) / 1000) : 0 }, u ? 429 : 401);
    }
    if (path === "/api/logout" && method === "POST") {
      return J({ ok: true }, 200, { "set-cookie": setCookie("", 0) });
    }

    // --- শুধু অ্যাডমিন ---
    if (path === "/api/state" && method === "PUT") {
      if (!adminOf(req)) return J({ error: "অনুমতি নেই বা সেশন শেষ" }, 401);
      const clean = cleanState(await readJSON(req, 900000));
      await getStore({ name: "shop", consistency: "strong" }).setJSON("state", clean);
      return J({ ok: true });
    }
    if (path === "/api/upload" && method === "POST") {
      if (!adminOf(req)) return J({ error: "অনুমতি নেই বা সেশন শেষ" }, 401);
      const b = await readJSON(req, 800000);
      const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(b?.data || ""));
      if (!m) return J({ error: "শুধু jpg/png/webp ছবি" }, 400);
      const buf = Buffer.from(m[2], "base64");
      if (buf.length < 100 || buf.length > 500 * 1024) return J({ error: "ছবি ৫০০KB এর মধ্যে হতে হবে" }, 413);
      const okMagic =
        (m[1] === "jpeg" && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) ||
        (m[1] === "png" && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) ||
        (m[1] === "webp" && buf.subarray(0, 4).toString() === "RIFF" && buf.subarray(8, 12).toString() === "WEBP");
      if (!okMagic) return J({ error: "ফাইলের ধরন মেলেনি" }, 400);
      const id = randomUUID();
      await getStore("shop-images").set(id, buf, { metadata: { type: "image/" + m[1] } });
      return J({ url: "/api/img/" + id });
    }
    return J({ error: "not found" }, 404);
  } catch (e) {
    if (e && e.status) return J({ error: e.message }, e.status);
    console.error("api error:", e && e.message);
    return J({ error: "সার্ভারে সমস্যা" }, 500);
  }
};
