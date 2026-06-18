# nuuson-api-gateway

Cloudflare Worker at `api.nuuson.dev`. Validates API keys and proxies requests to internal VPS services protected by Cloudflare Access.

## How it works

1. Caller sends `Authorization: Bearer nuu_<key>` to `api.nuuson.dev/v1/<service>/...`
2. Worker SHA-256 hashes the key and looks it up in the `API_KEYS` KV namespace
3. If missing or `valid: false` → 401
4. Checks key's `scopes` array includes the route's scope (or `all`) → 403 if not
5. Reads tier limits from KV (`tier:<name>:scope:<scope>` → `tier:<name>` → unlimited fallback)
6. Enforces rate limits via Durable Object (fixed-bucket sliding window) → 429 if exceeded; skipped if `rpm=0 && rpd=0` (unlimited tier)
7. Strips `Authorization`, injects CF Access service token headers, proxies to the backend internal subdomain
8. Backend response returned to caller

API keys are issued and managed by `nuuson-api-admin`. The KV namespace is shared between both services.

## Route table

`src/routes.js` maps URL prefixes to backend URLs:

```js
export const ROUTES = {
  '/v1/testing/': {
    backend: 'https://testing-internal.nuuson.dev',
    scope: 'testing',
  },
};
```

To register a new service: add one entry here (backend URL + scope name) and open a PR. The backend URL must be an internal subdomain protected by the same Cloudflare Access policy as the existing backends (service token: `nuuson-api-gateway`).

## One-time setup for a new deployment

### 1. Cloudflare Access service token

The Worker needs credentials to call CF Access-protected backends. These are set as Worker secrets (not in CI — they persist across deploys):

```bash
cd nuuson-api-gateway
npm install
npx wrangler secret put CF_ACCESS_CLIENT_ID
npx wrangler secret put CF_ACCESS_CLIENT_SECRET
```

Get the values from Tofu outputs:
```bash
tofu -chdir=../nwmain/infra/environments/prod output -json \
  | jq '{id: .gateway_access_client_id.value, secret: .gateway_access_client_secret.value}'
```

### 2. Vault role

CI fetches the Cloudflare API token from Vault to deploy the Worker. Create the role and policy once:

```bash
vault policy write project-nuuson-api-gateway - <<'EOF'
path "secret/data/infra/cloudflare" {
    capabilities = ["read"]
}
EOF

vault write auth/jwt/role/project-nuuson-api-gateway \
  role_type=jwt \
  bound_audiences="https://vault.nwilson5.dev" \
  user_claim=sub \
  policies=project-nuuson-api-gateway \
  ttl=15m
```

### 3. GitHub repo config

- **Variable**: `VAULT_ADDR` (e.g. `https://vault.nwilson5.dev`)

No secrets needed — deploy credentials come from Vault via OIDC.

## CI/CD

On pull request: unit tests (`npm test`) + dry-run bundle check (`wrangler deploy --dry-run`).
On push to main: deploy to Cloudflare.

Set `Deploy / validate` as a required status check on `main` in repo settings.

Worker secrets (`CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`) are never touched by CI — update them manually with `wrangler secret put` if they need to be rotated.

## Ops

Real-time log tail:
```bash
cd nuuson-api-gateway
npx wrangler tail nuuson-api-gateway
```

Test a key:
```bash
curl -s -H "Authorization: Bearer nuu_..." https://api.nuuson.dev/v1/testing/hello | jq .
```

Test without a key (should return 401):
```bash
curl -s https://api.nuuson.dev/v1/testing/hello | jq .
```
