import { afterEach, describe, expect, it, vi } from 'vitest';

import httpFetch, {
  ApiError,
  BackendDownError,
  expectOk,
  isBackendDown,
  isUnauthorized,
} from './http';
import { authHeaders, clearSession, storeSession } from './session';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
  vi.useRealTimers();
});

describe('http wrapper (ADR-0004 shared behaviour)', () => {
  it('resolves the orval envelope {status, data, headers}', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ status: 'ok' }), { status: 200 })),
    );
    const res = await httpFetch<{
      status: number;
      data: { status: string };
      headers: Headers;
    }>('/health');
    expect(res.status).toBe(200);
    expect(res.data).toEqual({ status: 'ok' });
    expect(res.headers).toBeInstanceOf(Headers);
  });

  it('sends the as-built X-Admin-Token + X-CSRF-Token twins from sessionStorage', async () => {
    storeSession('tok-123', 'csrf-456');
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await httpFetch('/api/v1/meta');
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get('X-Admin-Token')).toBe('tok-123');
    expect(headers.get('X-CSRF-Token')).toBe('csrf-456');
    expect(init.credentials).toBe('same-origin');
  });

  it('throws BackendDownError (network) when fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Promise.reject(new TypeError('Failed to fetch'))),
    );
    await expect(httpFetch('/health')).rejects.toMatchObject({
      name: 'BackendDownError',
      reason: 'network',
    });
  });

  it('throws BackendDownError (timeout) when the server does not answer', async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init?: RequestInit) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('Aborted', 'AbortError')),
            );
          }),
      ),
    );
    const pending = httpFetch('/health');
    const assertion = expect(pending).rejects.toMatchObject({
      name: 'BackendDownError',
      reason: 'timeout',
    });
    await vi.advanceTimersByTimeAsync(15_001);
    await assertion;
  });

  it('expectOk passes a success envelope through untouched', async () => {
    const ok = { status: 200 as const, data: { hello: 'world' }, headers: new Headers() };
    expect(expectOk(ok)).toBe(ok);
  });

  it('expectOk throws ApiError with the {error, details} shape', () => {
    const failure = {
      status: 403 as const,
      data: { error: 'Denied', details: { reason: 'nope' }, status: 'mfa_required' },
      headers: new Headers(),
    };
    try {
      expectOk(failure);
      expect.unreachable('expectOk must throw for a non-2xx envelope');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      const apiError = error as ApiError;
      expect(apiError.status).toBe(403);
      expect(apiError.message).toBe('Denied');
      expect(apiError.details).toEqual({ reason: 'nope' });
      expect(apiError.statusField).toBe('mfa_required');
      expect(apiError.body?.error).toBe('Denied');
    }
  });

  it('predicates classify failures honestly', () => {
    expect(isBackendDown(new BackendDownError('network', 'x'))).toBe(true);
    expect(isBackendDown(new ApiError(500, 'x'))).toBe(false);
    expect(isUnauthorized(new ApiError(401, 'x'))).toBe(true);
    expect(isUnauthorized(new ApiError(403, 'x'))).toBe(false);
  });

  it('authHeaders omits both twins when no session exists', () => {
    clearSession();
    expect(authHeaders()).toEqual({});
  });
});
