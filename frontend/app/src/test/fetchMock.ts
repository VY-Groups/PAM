import { vi } from 'vitest';

/** Build a fetch-shaped Response with the backend's JSON body. */
export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** The honest /auth/whoami 401 body (no credential presented). */
export const UNAUTHENTICATED_BODY = { error: 'Not authenticated' };

/** A minimal /health 200 body (ok posture) for the login footer. */
export const HEALTH_OK_BODY = {
  status: 'ok',
  database: 'ok',
  auth: 'open',
  algorithms: [],
  formats: [],
};

/**
 * An honest `GET /auth/whoami` 200 body for the open/dev posture
 * (openapi WhoAmI schema, required fields only).
 */
export const WHOAMI_OPEN_BODY = {
  mode: 'open',
  principal: 'open',
  role: 'admin',
  kind: 'open',
  operations: 'all',
  operations_count: 1,
};

/** Ready-made route: GET /auth/whoami answers `body` with `status`. */
export function whoamiRoute(body: unknown, status = 200) {
  return {
    match: (url: string) => url.includes('/auth/whoami'),
    respond: () => jsonResponse(status, body),
  };
}

/** Ready-made route: GET /health answers the ok posture. */
export function healthRoute() {
  return {
    match: (url: string) => url.includes('/health'),
    respond: () => jsonResponse(200, HEALTH_OK_BODY),
  };
}

/**
 * Install a URL-matching fetch mock. `routes` is consulted in order;
 * unmatched URLs reject (honest backend-down in tests, not silent success).
 */
export function stubFetch(
  routes: Array<{
    match: (url: string) => boolean;
    respond: (init?: RequestInit) => Response | Promise<Response>;
  }>,
): ReturnType<typeof vi.fn> {
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const route = routes.find((r) => r.match(url));
    if (!route) return Promise.reject(new TypeError(`Unhandled fetch: ${url}`));
    return Promise.resolve(route.respond(init));
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}
