const CERTS_TTL_MS = 60 * 60 * 1000;
const CERTS_MIN_REFETCH_MS = 60 * 1000;
const COUNTRY_CODE = /^[A-Za-z]{2}$/;

let certsCache = { keys: [], fetchedAt: 0 };

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    }

    let claims;
    try {
      claims = await verifyAccessJwt(request, env);
    } catch (err) {
      console.log(`Access JWT rejected: ${err.message}`);
      return new Response("Forbidden", { status: 403 });
    }

    const path = new URL(request.url).pathname.replace(/\/+$/, "");

    if (path === "/secure") {
      return identityPage(request, claims);
    }

    const match = path.match(/^\/secure\/([^/]+)$/);
    if (match) {
      return flagResponse(request, env, match[1]);
    }

    return new Response("Not Found", { status: 404 });
  },
};

function identityPage(request, claims) {
  const email = escapeHtml(claims.email);
  const timestamp = new Date(claims.iat * 1000).toISOString();
  const country = request.cf?.country ?? "XX";

  // "XX" (unknown) and non-ISO values like "T1" (Tor) have no flag, so render them as plain text.
  const countryHtml = COUNTRY_CODE.test(country) && country !== "XX"
    ? `<a href="/secure/${country}">${country}</a>`
    : escapeHtml(country);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Authenticated</title>
</head>
<body>
  <p>${email} authenticated at ${timestamp} from ${countryHtml}</p>
</body>
</html>`;

  return new Response(request.method === "HEAD" ? null : html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "private, no-store",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function flagResponse(request, env, code) {
  if (!COUNTRY_CODE.test(code)) {
    return new Response("Not Found", { status: 404 });
  }

  const object = await env.FLAGS.get(`${code.toLowerCase()}.svg`);
  if (!object) {
    return new Response("Flag not found", { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "image/svg+xml");
  }
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "private, max-age=3600");
  headers.set("X-Content-Type-Options", "nosniff");
  // SVGs can embed script; sandbox them since they are served top-level.
  headers.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox");

  return new Response(request.method === "HEAD" ? null : object.body, { headers });
}

async function verifyAccessJwt(request, env) {
  if (!env.TEAM_DOMAIN || !env.POLICY_AUD) throw new Error("TEAM_DOMAIN or POLICY_AUD not configured");
  const teamDomain = env.TEAM_DOMAIN.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ?? getCookie(request, "CF_Authorization");
  if (!token) throw new Error("missing token");

  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const header = JSON.parse(base64UrlDecodeText(encodedHeader));
  if (header.alg !== "RS256") throw new Error(`unexpected alg ${header.alg}`);

  const jwk = await getSigningKey(teamDomain, header.kid);
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64UrlDecode(encodedSignature),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
  );
  if (!valid) throw new Error("bad signature");

  const claims = JSON.parse(base64UrlDecodeText(encodedPayload));
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= now) throw new Error("token expired");
  if (typeof claims.nbf === "number" && claims.nbf > now + 60) throw new Error("token not yet valid");
  if (typeof claims.iat !== "number") throw new Error("no iat claim");
  if (claims.iss !== `https://${teamDomain}`) throw new Error(`unexpected issuer ${claims.iss}`);

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(env.POLICY_AUD)) throw new Error("audience mismatch");
  if (!claims.email) throw new Error("no email claim");

  return claims;
}

async function getSigningKey(teamDomain, kid) {
  const fresh = Date.now() - certsCache.fetchedAt < CERTS_TTL_MS;
  let jwk = fresh ? certsCache.keys.find((k) => k.kid === kid) : undefined;

  // Refetch on cache miss too, so a key rotation doesn't lock users out,
  // but at most once a minute so unknown kids can't force a fetch per request.
  if (!jwk && (!fresh || Date.now() - certsCache.fetchedAt >= CERTS_MIN_REFETCH_MS)) {
    const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
    if (!res.ok) throw new Error(`certs fetch failed: ${res.status}`);
    const { keys } = await res.json();
    certsCache = { keys, fetchedAt: Date.now() };
    jwk = keys.find((k) => k.kid === kid);
  }

  if (!jwk) throw new Error(`unknown kid ${kid}`);
  return jwk;
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;
  for (const pair of cookie.split(";")) {
    const [k, ...v] = pair.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function base64UrlDecode(input) {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function base64UrlDecodeText(input) {
  return new TextDecoder().decode(base64UrlDecode(input));
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
