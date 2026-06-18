import { ROUTES } from './routes.js';
export { RateLimiter } from './rate-limiter.js';

async function hashKey(rawKey) {
  const encoded = new TextEncoder().encode(rawKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function resolveLimits(env, tier, scope) {
  if (!tier) return { rpm: 0, rpd: 0 };
  const scopeRaw = await env.API_KEYS.get(`tier:${tier}:scope:${scope}`, { cacheTtl: 300 });
  if (scopeRaw) return JSON.parse(scopeRaw);
  const tierRaw = await env.API_KEYS.get(`tier:${tier}`, { cacheTtl: 300 });
  if (tierRaw) return JSON.parse(tierRaw);
  return { rpm: 0, rpd: 0 };
}

export default {
  async fetch(request, env) {
    const authHeader = request.headers.get('Authorization') ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'missing api key' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }

    const rawKey = authHeader.slice(7);
    const keyHash = await hashKey(rawKey);
    const entry = await env.API_KEYS.get(keyHash, { cacheTtl: 60 });

    if (!entry) {
      return new Response(JSON.stringify({ error: 'invalid api key' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }

    const keyData = JSON.parse(entry);
    if (!keyData.valid) {
      return new Response(JSON.stringify({ error: 'api key revoked' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    }

    const url = new URL(request.url);
    for (const [prefix, route] of Object.entries(ROUTES)) {
      if (url.pathname.startsWith(prefix)) {
        if (!keyData.scopes.includes(route.scope) && !keyData.scopes.includes('all')) {
          return new Response(JSON.stringify({ error: 'insufficient scope' }), {
            status: 403,
            headers: { 'content-type': 'application/json' },
          });
        }

        const limits = await resolveLimits(env, keyData.tier, route.scope);

        // rpm=0 && rpd=0 means unlimited — skip the DO check entirely
        if (limits.rpm !== 0 || limits.rpd !== 0) {
          const id = env.RATE_LIMITER.idFromName(keyHash);
          const stub = env.RATE_LIMITER.get(id);
          const rlRes = await stub.fetch('https://internal/check', {
            method: 'POST',
            body: JSON.stringify({ rpm: limits.rpm, rpd: limits.rpd }),
          });
          const rl = await rlRes.json();

          if (!rl.allowed) {
            const retryAfter = Math.max(0, rl.reset_rpm - Math.floor(Date.now() / 1000));
            return new Response(JSON.stringify({ error: 'rate limit exceeded' }), {
              status: 429,
              headers: {
                'content-type': 'application/json',
                'Retry-After': String(retryAfter),
                'X-RateLimit-Limit': String(limits.rpm),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': String(rl.reset_rpm),
              },
            });
          }
        }

        const targetUrl = route.backend + url.pathname + url.search;

        const outboundHeaders = new Headers(request.headers);
        outboundHeaders.delete('Authorization');
        outboundHeaders.set('CF-Access-Client-Id', env.CF_ACCESS_CLIENT_ID);
        outboundHeaders.set('CF-Access-Client-Secret', env.CF_ACCESS_CLIENT_SECRET);

        return fetch(new Request(targetUrl, {
          method: request.method,
          headers: outboundHeaders,
          body: request.body,
        }));
      }
    }

    return new Response(JSON.stringify({ error: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  },
};
