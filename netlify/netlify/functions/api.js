import { getStore } from "@netlify/blobs";

const J = (o, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const te = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha(x) { return hex(await crypto.subtle.digest("SHA-256", te.encode(x))); }
async function hmac(k, m) {
  const key = await crypto.subtle.importKey("raw", te.encode(k), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, te.encode(m)));
}
const eq = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
const str = (v, n) => String(v == null ? "" : v).slice(0, n);

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").split("/");
  const m = req.method;
  const site = getStore({ name: "site", consistency: "strong" });
  const orders = getStore({ name: "orders", consistency: "strong" });
  const images = getStore({ name: "images" });

  const storedPw = (await site.get("pw")) || "";
  const secret = (process.env.TOKEN_SECRET || "") + (process.env.ADMIN_PASSWORD || "") + storedPw;
  const mkToken = async () => { const exp = Date.now() + 12 * 3600 * 1000; return exp + "." + (await hmac(secret, "admin" + exp)); };
  const authed = async () => {
    const t = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
    const [exp, sig] = t.split(".");
    if (!exp || !sig || +exp < Date.now() || !secret) return false;
    return eq(sig, await hmac(secret, "admin" + exp));
  };
  const body = async () => { try { return await req.json(); } catch { return null; } };

  try {
    // ---- public ----
    if (path[0] === "data" && m === "GET") return J((await site.get("data", { type: "json" })) || null);

    if (path[0] === "img" && m === "GET") {
      const r = await images.getWithMetadata(path[1], { type: "arrayBuffer" });
      if (!r) return new Response("not found", { status: 404 });
      return new Response(r.data, { headers: { "content-type": (r.metadata && r.metadata.type) || "image/jpeg", "cache-control": "public, max-age=31536000, immutable" } });
    }

    if (path[0] === "login" && m === "POST") {
      const b = await body();
      const pw = str(b && b.password, 200);
      if (!storedPw && !process.env.ADMIN_PASSWORD) return J({ error: "ADMIN_PASSWORD дар Netlify танзим нашудааст." }, 500);
      const ok = storedPw ? eq(await sha("ms:" + pw), storedPw) : eq(pw, process.env.ADMIN_PASSWORD);
      if (!ok) return J({ error: "Парол нодуруст аст." }, 401);
      return J({ token: await mkToken() });
    }

    if (path[0] === "order" && m === "POST" && !path[1]) {
      const b = await body();
      if (!b || !Array.isArray(b.items) || !b.items.length || b.items.length > 50) return J({ error: "bad" }, 400);
      const no = str(b.no, 40);
      if (!/^[A-Za-z0-9-]{6,40}$/.test(no)) return J({ error: "bad" }, 400);
      if (await orders.get(no)) return J({ ok: true });
      const items = b.items.map((i) => ({ t: str(i.t, 200), s: str(i.s, 30), q: Math.max(1, Math.min(999, +i.q || 1)), p: Math.max(0, +i.p || 0) }));
      const o = { no, ts: Date.now(), items, tot: items.reduce((a, i) => a + i.p * i.q, 0), cust: str(b.cust, 200), phone: str(b.phone, 60), addr: str(b.addr, 300), st: "Нав" };
      await orders.setJSON(no, o);
      return J({ ok: true });
    }

    // ---- admin ----
    if (!(await authed())) return J({ error: "unauthorized" }, 401);

    if (path[0] === "data" && m === "PUT") {
      const b = await body();
      if (!b || !b.S || !Array.isArray(b.P) || !Array.isArray(b.C)) return J({ error: "bad" }, 400);
      delete b.S.ph;
      await site.setJSON("data", { S: b.S, P: b.P, C: b.C });
      return J({ ok: true });
    }

    if (path[0] === "upload" && m === "POST") {
      const ct = (req.headers.get("content-type") || "").split(";")[0];
      if (!/^image\//.test(ct)) return J({ error: "image only" }, 400);
      const buf = await req.arrayBuffer();
      if (buf.byteLength > 5.5e6) return J({ error: "too large" }, 413);
      const key = crypto.randomUUID();
      await images.set(key, buf, { metadata: { type: ct } });
      return J({ url: "/api/img/" + key });
    }

    if (path[0] === "orders" && m === "GET") {
      const { blobs } = await orders.list();
      const all = (await Promise.all(blobs.map((b) => orders.get(b.key, { type: "json" })))).filter(Boolean);
      all.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      return J(all);
    }

    if (path[0] === "order" && path[1]) {
      const id = decodeURIComponent(path[1]);
      if (!/^[A-Za-z0-9-]{3,60}$/.test(id)) return J({ error: "bad" }, 400);
      if (m === "PUT") {
        const b = await body();
        if (!b || !Array.isArray(b.items)) return J({ error: "bad" }, 400);
        b.no = id;
        await orders.setJSON(id, b);
        return J({ ok: true });
      }
      if (m === "DELETE") { await orders.delete(id); return J({ ok: true }); }
    }

    if (path[0] === "password" && m === "POST") {
      const b = await body();
      const pw = str(b && b.pw, 200);
      if (pw.length < 6) return J({ error: "short" }, 400);
      await site.set("pw", await sha("ms:" + pw));
      const sp = await site.get("pw");
      const exp = Date.now() + 12 * 3600 * 1000;
      const sec = (process.env.TOKEN_SECRET || "") + (process.env.ADMIN_PASSWORD || "") + sp;
      return J({ token: exp + "." + (await hmac(sec, "admin" + exp)) });
    }

    return J({ error: "not found" }, 404);
  } catch (e) {
    return J({ error: "server error" }, 500);
  }
};

export const config = { path: "/api/*" };
