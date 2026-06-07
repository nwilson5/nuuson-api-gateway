import { ROUTES } from './routes.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    for (const [prefix, backend] of Object.entries(ROUTES)) {
      if (url.pathname.startsWith(prefix)) {
        const targetPath = url.pathname.slice(prefix.length) || '/';
        const targetUrl = backend + targetPath + url.search;
        const proxied = new Request(targetUrl, {
          method: request.method,
          headers: request.headers,
          body: request.body,
        });
        return fetch(proxied);
      }
    }

    return new Response(JSON.stringify({ error: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  },
};
