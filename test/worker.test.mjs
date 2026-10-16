import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const TEAM = "myteam.cloudflareaccess.com";
const AUD = "aud123";
const env = {
  TEAM_DOMAIN: TEAM,
  POLICY_AUD: AUD,
  FLAGS: {
    async get(key) {
      if (key !== "gb.svg") return null;
      return {
        body: "<svg/>",
        httpEtag: '"abc"',
        writeHttpMetadata(h) {
          h.set("Content-Type", "image/svg+xml");
        },
      };
    },
  },
};

const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const jwk = { ...(await crypto.subtle.exportKey("jwk", publicKey)), kid: "k1", alg: "RS256", use: "sig" };

let certFetches = 0;
globalThis.fetch = async (url) => {
  if (url !== `https://${TEAM}/cdn-cgi/access/certs`) throw new Error(`unexpected fetch ${url}`);
  certFetches++;
  return new Response(JSON.stringify({ keys: [jwk] }));
};

const b64u = (b) => Buffer.from(b).toString("base64url");
async function sign(claims, kid = "k1") {
  const h = b64u(JSON.stringify({ alg: "RS256", kid }));
  const p = b64u(JSON.stringify(claims));
  const s = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(s)}`;
}

const now = Math.floor(Date.now() / 1000);
const good = { email: "a<b>@cloudflare.com", iat: now - 60, exp: now + 3600, iss: `https://${TEAM}`, aud: [AUD] };
const token = await sign(good);

async function call(path, tok, { cookie = false, country = "GB", method = "GET", e = env } = {}) {
  const headers = {};
  if (tok) {
    if (cookie) headers.Cookie = `x=1; CF_Authorization=${tok}`;
    else headers["Cf-Access-Jwt-Assertion"] = tok;
  }
  const req = new Request(`https://tunnel.example.com${path}`, { method, headers });
  Object.defineProperty(req, "cf", { value: { country } });
  const res = await worker.fetch(req, e);
  return { status: res.status, headers: res.headers, body: await res.text() };
}

test("identity page with valid header token", async () => {
  const r = await call("/secure", token);
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type"), /text\/html/);
  assert.match(r.body, /a&lt;b&gt;@cloudflare\.com authenticated at \S+Z from <a href="\/secure\/GB">GB<\/a>/);
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.match(r.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.match(r.headers.get("cache-control"), /no-store/);
});

test("trailing slash and cookie fallback", async () => {
  assert.equal((await call("/secure/", token)).status, 200);
  assert.equal((await call("/secure", token, { cookie: true })).status, 200);
});

test("non-ISO and unknown countries are plain text", async () => {
  for (const country of ["T1", "XX"]) {
    const r = await call("/secure", token, { country });
    assert.match(r.body, new RegExp(`from ${country}</p>`));
    assert.doesNotMatch(r.body, /<a /);
  }
});

test("flag served from R2", async () => {
  const r = await call("/secure/GB", token);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("content-type"), "image/svg+xml");
  assert.match(r.headers.get("content-security-policy"), /sandbox/);
  assert.equal(r.body, "<svg/>");
  assert.equal((await call("/secure/gb", token)).status, 200);
});

test("bad flag paths return 404", async () => {
  for (const p of ["/secure/ZZ", "/secure/..%2fx", "/secure/%47B", "/secure/gb-eng", "/secure/GB/x", "/securefoo"]) {
    assert.equal((await call(p, token)).status, 404, p);
  }
});

test("HEAD has no body, other methods are rejected", async () => {
  const head = await call("/secure", token, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.body, "");
  const post = await call("/secure", token, { method: "POST" });
  assert.equal(post.status, 405);
});

test("invalid tokens are rejected with 403", async () => {
  const cases = {
    missing: null,
    malformed: "abc",
    wrongAud: await sign({ ...good, aud: ["x"] }),
    noAud: await sign({ ...good, aud: undefined }),
    wrongIss: await sign({ ...good, iss: "https://evil.cloudflareaccess.com" }),
    expired: await sign({ ...good, exp: now - 1 }),
    noExp: await sign({ ...good, exp: undefined }),
    noIat: await sign({ ...good, iat: undefined }),
    notYetValid: await sign({ ...good, nbf: now + 3600 }),
    noEmail: await sign({ ...good, email: undefined }),
    tampered: token.replace(/\.[^.]+\./, `.${b64u(JSON.stringify({ ...good, email: "x@y" }))}.`),
    algNone: `${b64u(JSON.stringify({ alg: "none", kid: "k1" }))}.${b64u(JSON.stringify(good))}.`,
  };
  for (const [name, tok] of Object.entries(cases)) {
    const r = await call("/secure", tok);
    assert.equal(r.status, 403, name);
    assert.equal(r.body, "Forbidden", name);
  }
});

test("fails closed when config is missing", async () => {
  for (const missing of ["TEAM_DOMAIN", "POLICY_AUD"]) {
    const r = await call("/secure", token, { e: { ...env, [missing]: undefined } });
    assert.equal(r.status, 403, missing);
  }
});

test("unknown kids cannot force a certs fetch per request", async () => {
  await call("/secure", token); // warm the cache
  const before = certFetches;
  const forged = await sign(good, "unknown");
  for (let i = 0; i < 5; i++) assert.equal((await call("/secure", forged)).status, 403);
  assert.ok(certFetches - before <= 1, `fetched certs ${certFetches - before} times`);
});
