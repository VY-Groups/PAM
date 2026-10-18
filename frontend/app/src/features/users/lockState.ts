import type { ConsoleUser } from './types';

/**
 * ADR-0016 batch 11.7 - the lockout derivation for the table chips and the
 * KPI tile: an account is locked while its captured `locked_until` lies in
 * the future (the backend refuses sign-in until then; the admin unlock
 * clears the counter and the timestamp). The reference instant is read
 * inside this helper exactly like `settingsAgo`'s relative clock: lock
 * state is time-derived by contract, and the react-hooks purity rule keeps
 * `Date.now()` out of the component's render body.
 */
export function isLocked(user: ConsoleUser): boolean {
  return user.locked_until !== null && new Date(user.locked_until).getTime() > Date.now();
}
