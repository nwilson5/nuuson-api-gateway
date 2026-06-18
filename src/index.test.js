import { describe, it, expect, vi, afterEach } from 'vitest';
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

describe('global settings', () => {
  it('503 when disable_all_apis is enabled', async () => {
    const env = makeEnv({ 'global:disable_all_apis': JSON.stringify({ enabled: true }) });
    const res = await worker.fetch(req('/v1/testing/health', { Authorization: 'Bearer any' }), env);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'service unavailable' });
  });

  it('proceeds normally when disable_all_apis is disabled', async () => {
    const env = makeEnv({ 'global:disable_all_apis': JSON.stringify({ enabled: false }) });
    const res = await worker.fetch(req('/v1/testing/health', { Authorization: 'Bearer any' }), env);
    expect(res.status).toBe(401);
  });

  it('proceeds normally when disable_all_apis key is absent', async () => {
    const res = await worker.fetch(req('/v1/testing/health', { Authorization: 'Bearer any' }), makeEnv());
    expect(res.status).toBe(401);
  });
});

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

function makeRateLimiter(rl = {}) {
  const defaults = { allowed: true, remaining_rpm: 59, remaining_rpd: 499, reset_rpm: 9999999999 };
  const response = { ...defaults, ...rl };
  return {
    idFromName: () => 'test-id',
    get: () => ({
      fetch: vi.fn().mockResolvedValue(
        new Response(JSON.stringify(response), { headers: { 'content-type': 'application/json' } }),
      ),
    }),
  };
}

function makeEnvWithLimits(kvEntries = {}, rl = {}) {
  return { ...makeEnv(kvEntries), RATE_LIMITER: makeRateLimiter(rl) };
}

describe('rate limiting', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('X-RateLimit-* headers present on successful proxied response', async () => {
    const raw = 'rl-headers-key';
    const hash = await hashKey(raw);
    const kv = {
      [hash]: keyEntry(),
      [`tier:free:scope:testing`]: null,
      [`tier:free`]: JSON.stringify({ rpm: 60, rpd: 500 }),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })));
    const res = await worker.fetch(
      req('/v1/testing/path', { Authorization: `Bearer ${raw}` }),
      makeEnvWithLimits(kv),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('X-RateLimit-Limit')).toBe('60');
    expect(res.headers.get('X-RateLimit-Remaining')).toBe('59');
    expect(res.headers.get('X-RateLimit-Reset')).toBeTruthy();
  });

  it('429 with Retry-After and X-RateLimit-* when DO denies request', async () => {
    const raw = 'rl-exceeded-key';
    const hash = await hashKey(raw);
    const kv = {
      [hash]: keyEntry(),
      [`tier:free`]: JSON.stringify({ rpm: 60, rpd: 500 }),
    };
    const res = await worker.fetch(
      req('/v1/testing/path', { Authorization: `Bearer ${raw}` }),
      makeEnvWithLimits(kv, { allowed: false, reset_rpm: 9999999999 }),
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: 'rate limit exceeded' });
    expect(res.headers.get('Retry-After')).toBeTruthy();
    expect(res.headers.get('X-RateLimit-Limit')).toBe('60');
    expect(res.headers.get('X-RateLimit-Remaining')).toBe('0');
  });

  it('unlimited tier skips DO entirely and omits rate limit headers', async () => {
    const raw = 'unlimited-key';
    const hash = await hashKey(raw);
    const kv = {
      [hash]: keyEntry({ tier: 'unlimited' }),
      [`tier:unlimited`]: JSON.stringify({ rpm: 0, rpd: 0 }),
    };
    const doStub = makeRateLimiter();
    const doFetch = doStub.get().fetch;
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })));
    const res = await worker.fetch(
      req('/v1/testing/path', { Authorization: `Bearer ${raw}` }),
      { ...makeEnv(kv), RATE_LIMITER: doStub },
    );
    expect(res.status).toBe(200);
    expect(doFetch).not.toHaveBeenCalled();
    expect(res.headers.get('X-RateLimit-Limit')).toBeNull();
  });

  it('scope override takes precedence over tier limit', async () => {
    const raw = 'scope-override-key';
    const hash = await hashKey(raw);
    const kv = {
      [hash]: keyEntry(),
      [`tier:free:scope:testing`]: JSON.stringify({ rpm: 10, rpd: 100 }),
      [`tier:free`]: JSON.stringify({ rpm: 60, rpd: 500 }),
    };
    const doFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ allowed: true, remaining_rpm: 9, remaining_rpd: 99, reset_rpm: 9999999999 }),
        { headers: { 'content-type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })));
    await worker.fetch(
      req('/v1/testing/path', { Authorization: `Bearer ${raw}` }),
      { ...makeEnv(kv), RATE_LIMITER: { idFromName: () => 'id', get: () => ({ fetch: doFetch }) } },
    );
    const doCall = JSON.parse(doFetch.mock.calls[0][1].body ?? '{}');
    expect(doCall.rpm).toBe(10);
    expect(doCall.rpd).toBe(100);
  });

  it('falls back to tier limit when no scope override exists', async () => {
    const raw = 'tier-fallback-key';
    const hash = await hashKey(raw);
    const kv = {
      [hash]: keyEntry(),
      [`tier:free`]: JSON.stringify({ rpm: 60, rpd: 500 }),
    };
    const doFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ allowed: true, remaining_rpm: 59, remaining_rpd: 499, reset_rpm: 9999999999 }),
        { headers: { 'content-type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })));
    await worker.fetch(
      req('/v1/testing/path', { Authorization: `Bearer ${raw}` }),
      { ...makeEnv(kv), RATE_LIMITER: { idFromName: () => 'id', get: () => ({ fetch: doFetch }) } },
    );
    const doCall = JSON.parse(doFetch.mock.calls[0][1].body ?? '{}');
    expect(doCall.rpm).toBe(60);
    expect(doCall.rpd).toBe(500);
  });
});

function makeCtx() {
  return { waitUntil: vi.fn((p) => p) };
}

function makeUsage() {
  return { writeDataPoint: vi.fn() };
}

describe('analytics', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('writes usage on successful proxied response with backend status code', async () => {
    const raw = 'analytics-proxy-key';
    const hash = await hashKey(raw);
    const kv = { [hash]: keyEntry() };
    const usage = makeUsage();
    const ctx = makeCtx();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 201 })));
    await worker.fetch(req('/v1/testing/path', { Authorization: `Bearer ${raw}` }), { ...makeEnv(kv), USAGE: usage }, ctx);
    expect(ctx.waitUntil).toHaveBeenCalledOnce();
    const dp = usage.writeDataPoint.mock.calls[0][0];
    expect(dp.blobs[0]).toBe('u1');
    expect(dp.blobs[2]).toBe('free');
    expect(dp.blobs[3]).toBe('testing');
    expect(dp.doubles[1]).toBe(201);
    expect(dp.indexes[0]).toBe('u1');
  });

  it('writes usage with status 403 on scope denied', async () => {
    const raw = 'analytics-403-key';
    const hash = await hashKey(raw);
    const kv = { [hash]: keyEntry({ scopes: ['admin'] }) };
    const usage = makeUsage();
    const ctx = makeCtx();
    await worker.fetch(req('/v1/testing/path', { Authorization: `Bearer ${raw}` }), { ...makeEnv(kv), USAGE: usage }, ctx);
    expect(ctx.waitUntil).toHaveBeenCalledOnce();
    const dp = usage.writeDataPoint.mock.calls[0][0];
    expect(dp.doubles[1]).toBe(403);
  });

  it('writes usage with status 429 on rate limit exceeded', async () => {
    const raw = 'analytics-429-key';
    const hash = await hashKey(raw);
    const kv = { [hash]: keyEntry(), [`tier:free`]: JSON.stringify({ rpm: 60, rpd: 500 }) };
    const usage = makeUsage();
    const ctx = makeCtx();
    await worker.fetch(
      req('/v1/testing/path', { Authorization: `Bearer ${raw}` }),
      { ...makeEnvWithLimits(kv, { allowed: false, reset_rpm: 9999999999 }), USAGE: usage },
      ctx,
    );
    expect(ctx.waitUntil).toHaveBeenCalledOnce();
    const dp = usage.writeDataPoint.mock.calls[0][0];
    expect(dp.doubles[1]).toBe(429);
  });

  it('does not write usage on 401 (no key data available)', async () => {
    const usage = makeUsage();
    const ctx = makeCtx();
    await worker.fetch(req('/v1/testing/path'), { ...makeEnv(), USAGE: usage }, ctx);
    expect(ctx.waitUntil).not.toHaveBeenCalled();
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
