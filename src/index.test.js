import { describe, it, expect, vi, beforeAll } from 'vitest';
import worker from './index.js';

async function hashKey(raw) {
  const encoded = new TextEncoder().encode(raw);
  const buf = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function makeEnv(kvEntries = {}) {
  return {
    API_KEYS: { get: (key) => Promise.resolve(kvEntries[key] ?? null) },
    CF_ACCESS_CLIENT_ID: 'test-id',
    CF_ACCESS_CLIENT_SECRET: 'test-secret',
  };
}

function req(path, headers = {}) {
  return new Request(`https://api.nuuson.dev${path}`, { headers });
}

function keyEntry(overrides = {}) {
  return JSON.stringify({ id: 'u1', valid: true, scopes: ['testing'], tier: 'free', ...overrides });
}

describe('auth', () => {
  it('401 missing api key — no Authorization header', async () => {
    const res = await worker.fetch(req('/v1/testing/health'), makeEnv());
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'missing api key' });
  });

  it('401 missing api key — non-Bearer scheme', async () => {
    const res = await worker.fetch(req('/v1/testing/health', { Authorization: 'Basic abc' }), makeEnv());
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'missing api key' });
  });

  it('401 invalid api key — key not in KV', async () => {
    const res = await worker.fetch(
      req('/v1/testing/health', { Authorization: 'Bearer not-a-real-key' }),
      makeEnv(),
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid api key' });
  });

  it('401 api key revoked — valid: false in KV', async () => {
    const raw = 'revoked-key';
    const hash = await hashKey(raw);
    const res = await worker.fetch(
      req('/v1/testing/health', { Authorization: `Bearer ${raw}` }),
      makeEnv({ [hash]: keyEntry({ valid: false }) }),
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'api key revoked' });
  });
});

describe('scope', () => {
  it('403 insufficient scope — key lacks route scope', async () => {
    const raw = 'no-scope-key';
    const hash = await hashKey(raw);
    const res = await worker.fetch(
      req('/v1/testing/health', { Authorization: `Bearer ${raw}` }),
      makeEnv({ [hash]: keyEntry({ scopes: ['admin'] }) }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'insufficient scope' });
  });

  it('403 insufficient scope — empty scopes array', async () => {
    const raw = 'empty-scope-key';
    const hash = await hashKey(raw);
    const res = await worker.fetch(
      req('/v1/testing/health', { Authorization: `Bearer ${raw}` }),
      makeEnv({ [hash]: keyEntry({ scopes: [] }) }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'insufficient scope' });
  });

  it('"all" scope bypasses route scope check', async () => {
    const raw = 'all-scope-key';
    const hash = await hashKey(raw);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })));
    const res = await worker.fetch(
      req('/v1/testing/health', { Authorization: `Bearer ${raw}` }),
      makeEnv({ [hash]: keyEntry({ scopes: ['all'] }) }),
    );
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
    vi.unstubAllGlobals();
  });
});

describe('routing', () => {
  it('404 not found — no matching route', async () => {
    const raw = 'route-test-key';
    const hash = await hashKey(raw);
    const res = await worker.fetch(
      req('/v1/unknown/', { Authorization: `Bearer ${raw}` }),
      makeEnv({ [hash]: keyEntry({ scopes: ['all'] }) }),
    );
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'not found' });
  });
});
