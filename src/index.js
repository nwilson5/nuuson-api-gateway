import { ROUTES } from './routes.js';

async function hashKey(rawKey) {
  const encoded = new TextEncoder().encode(rawKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
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
    const entry = await env.API_KEYS.get(keyHash);

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
    for (const [prefix, backend] of Object.entries(ROUTES)) {
      if (url.pathname.startsWith(prefix)) {
        const targetUrl = backend + url.pathname + url.search;

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
