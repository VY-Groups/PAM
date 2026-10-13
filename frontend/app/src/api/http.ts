/**
 * Shared API wrapper (plan §3 `api/http.ts`, ADR-0004).
 *
 * orval's generated client calls this mutator as `httpFetch<T>(url, init)`.
 * orval's fetch contract expects a `{status, data, headers}` envelope for
 * every HTTP response, so HTTP-level failures are returned in the envelope
 * (narrow with `res.status`, or throw them with `expectOk`). Transport
 * failures (network, timeout) throw `BackendDownError` - the single
 * backend-down signal for the whole app (plan §5: every screen degrades the
 * same way).
 *
 * Auth headers follow the as-built legacy convention: the two sessionStorage
 * twins sent as `X-Admin-Token` + `X-CSRF-Token` (deliberate keep, F0
 * findings; proven live by the gate).
 */

import { authHeaders } from './session';

/** One request timeout for every call; a dead backend fails fast and honestly. */
const REQUEST_TIMEOUT_MS = 15_000;

export interface HttpErrorBody {
  error?: string;
  details?: unknown;
  /**
   * Runtime-only fields the login flow relies on (legacy login.html proves
   * them; the contract's Error schema does not model them although the
   * /auth/login 403 description names them - recorded as a contract gap in
   * docs/HANDOFF.md, to be fixed in the contract with backend lockstep).
   */
  status?: string;
  challenge?: string;
  methods_allowed?: string[];
  enrol_ticket?: string;
}

/** The envelope every generated call resolves with (orval fetch contract). */
export interface HttpEnvelope<T> {
  status: number;
  data: T;
  headers: Headers;
}

/** Non-2xx raised by `expectOk`: `{error, details}` shape (errors.py). */
export class ApiError extends Error {
  readonly status: number;
  readonly details: unknown;
  readonly statusField?: string;
  /** The full error body - carries the login flow's runtime-only fields. */
  readonly body?: HttpErrorBody;

  constructor(
    status: number,
    message: string,
    details?: unknown,
    statusField?: string,
    body?: HttpErrorBody,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
    this.statusField = statusField;
    this.body = body;
  }
}

/** Network failure or timeout: the shared backend-down signal (plan §5). */
export class BackendDownError extends Error {
  readonly reason: 'network' | 'timeout';

  constructor(reason: 'network' | 'timeout', message: string) {
    super(message);
    this.name = 'BackendDownError';
    this.reason = reason;
  }
}

/** True for "the license server is unreachable" - screens show the shared state. */
export function isBackendDown(error: unknown): error is BackendDownError {
  return error instanceof BackendDownError;
}

/** True for an authentication refusal (401). */
export function isUnauthorized(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 401;
}

/**
 * Narrow a generated call's envelope to its success arm, or throw the
 * `{error, details}` failure as `ApiError`. This is the standard way
 * features consume the client: `expectOk(await getApiV1...)`.
 */
export function expectOk<T extends HttpEnvelope<unknown>>(
  response: T,
): Extract<T, { status: 200 | 201 | 202 }> {
  if (response.status >= 400) {
    const body = (response.data ?? {}) as HttpErrorBody;
    throw new ApiError(
      response.status,
      body.error ?? `Request failed (${response.status})`,
      body.details,
      body.status,
      body,
    );
  }
  return response as Extract<T, { status: 200 | 201 | 202 }>;
}

/** orval mutator: generated code calls `mutator<T>(url, init)`. */
async function httpFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const method = init?.method ?? 'GET';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const callerSignal = init?.signal;
  const onCallerAbort = () => controller.abort();
  callerSignal?.addEventListener('abort', onCallerAbort);

  let response: Response;
  try {
    const headers = new Headers(init?.headers);
    headers.set('Accept', 'application/json');
    for (const [name, value] of Object.entries(authHeaders())) {
      headers.set(name, value);
    }
    response = await fetch(url, {
      ...init,
      headers,
      credentials: 'same-origin',
      signal: controller.signal,
    });
  } catch (error) {
    if (callerSignal?.aborted) throw error; // caller cancelled deliberately
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new BackendDownError(
        'timeout',
        `Request timed out after ${REQUEST_TIMEOUT_MS}ms: ${method} ${url}`,
      );
    }
    throw new BackendDownError(
      'network',
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    clearTimeout(timer);
    callerSignal?.removeEventListener('abort', onCallerAbort);
  }

  let data: unknown;
  if (response.status !== 204) {
    const text = await response.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = undefined;
      }
    }
  }

  const envelope: HttpEnvelope<unknown> = {
    status: response.status,
    data,
    headers: response.headers,
  };
  return envelope as T;
}

export default httpFetch;
export { httpFetch as customFetch };
