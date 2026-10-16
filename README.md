# secure-identity

Cloudflare Worker served on `tunnel.originserver.uk/secure` and `tunnel.originserver.uk/secure/*`, behind Cloudflare Access. The two routes match exactly what the Access application covers, so the Worker never runs on a path Access doesn't protect (a single `/secure*` route would also match `/securefoo`).

- `GET /secure` returns HTML: `${EMAIL} authenticated at ${TIMESTAMP} from ${COUNTRY}`. The country is a link to `/secure/${COUNTRY}`.
- `GET /secure/${COUNTRY}` returns that country's flag (`image/svg+xml`) from a private R2 bucket.

## How it works

- **Identity:** the Worker verifies the Access JWT (`Cf-Access-Jwt-Assertion` header, falling back to the `CF_Authorization` cookie). It checks the RS256 signature against the team's public keys at `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, then checks `exp`, `nbf`, `iss`, `aud` and that `iat` and an email are present. The algorithm is pinned to RS256. Requests that fail any check get a generic `403` (the reason is only logged), and the Worker also returns `403` if `TEAM_DOMAIN` or `POLICY_AUD` isn't configured. This protects the Worker even if the Access application is misconfigured.
- **Timestamp:** the JWT's `iat` claim, which is when Access issued the token for this application. With an existing Access session from another application, this can be later than the original IdP login.
- **Country:** `request.cf.country`, set by Cloudflare. Values with no flag (`XX` unknown, `T1` Tor) are shown as plain text.
- **Flags:** read through an R2 binding (`FLAGS`). The bucket has no public access. The country code is checked against `^[A-Za-z]{2}$` before it is used as an object key.
- `workers_dev` and preview URLs are disabled, so the Worker is only reachable through the Access-protected routes.

## Setup

Prerequisites: Node.js 22 or later, a zone on Cloudflare, and a self-hosted Access application covering `<hostname>/secure` (an Access path also covers its subpaths).

1. Install dependencies and log in:
   ```sh
   npm install
   npx wrangler login
   ```
2. Create the bucket (R2 buckets are private by default) and upload the flags:
   ```sh
   npx wrangler r2 bucket create flags
   ```
   The flags are the [flag-icons](https://github.com/lipis/flag-icons) 4x3 SVGs (MIT licence), named by lowercase ISO code (e.g. `pt.svg`) at the top level of the bucket. For this deployment, all 271 were uploaded through the R2 dashboard (bucket → Objects → Upload). Single files can also be uploaded with Wrangler:
   ```sh
   npx wrangler r2 object put flags/pt.svg --file pt.svg --content-type image/svg+xml --remote
   ```
3. Edit `wrangler.toml`:
   - `routes`: your hostname and zone
   - `TEAM_DOMAIN`: your Zero Trust team domain (e.g. `yourteam.cloudflareaccess.com`)
   - `POLICY_AUD`: the Access application's Application Audience (AUD) tag
4. Deploy:
   ```sh
   npx wrangler deploy
   ```

## Testing

Unit tests use Node's built-in test runner (no extra dependencies). They sign tokens with a locally generated key and mock the certs endpoint and R2:

```sh
npm test
```

Against the live deployment:

```sh
# Unauthenticated: should redirect (302) to the Access login page
curl -sI https://tunnel.originserver.uk/secure

# Live logs
npx wrangler tail
```

Then open `https://tunnel.originserver.uk/secure` in a browser, sign in, and click the country link.
