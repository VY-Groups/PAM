/**
 * Console session storage (plan §3 `api/http.ts` auth half).
 *
 * The two storage keys are the legacy names - a deliberate keep
 * (docs/frontend/F0_FINDINGS.md, P3): the live gate and every legacy screen
 * read `aegispam_admin_token` / `aegispam_admin_csrf`, so the strangler
 * app shares the same session while both UIs coexist.
 */

export const TOKEN_KEY = 'aegispam_admin_token';
export const CSRF_KEY = 'aegispam_admin_csrf';

function read(key: string): string | null {
  try {
    return globalThis.sessionStorage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    globalThis.sessionStorage?.setItem(key, value);
  } catch {
    /* storage unavailable: the request just goes without the twin */
  }
}

function remove(key: string): void {
  try {
    globalThis.sessionStorage?.removeItem(key);
  } catch {
    /* ignore */
  }
}

/** The mint from POST /auth/login: bearer + CSRF twins, stored once (legacy contract). */
export function storeSession(sessionToken: string, csrfToken?: string): void {
  write(TOKEN_KEY, sessionToken);
  if (csrfToken) write(CSRF_KEY, csrfToken);
}

/** Local logout: clears both twins (happens even when the backend is down). */
export function clearSession(): void {
  remove(TOKEN_KEY);
  remove(CSRF_KEY);
}

/** True when this browser holds a session twin. */
export function hasSession(): boolean {
  return read(TOKEN_KEY) !== null;
}

/** The as-built credential headers (legacy screens send exactly these two). */
export function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const token = read(TOKEN_KEY);
  if (token) headers['X-Admin-Token'] = token;
  const csrf = read(CSRF_KEY);
  if (csrf) headers['X-CSRF-Token'] = csrf;
  return headers;
}
