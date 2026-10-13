/**
 * Query key factory (plan §3 `api/queryKeys.ts`).
 * Every cache key in the app starts here so invalidation stays greppable.
 */
export const queryKeys = {
  whoami: ['auth', 'whoami'] as const,
  health: ['health'] as const,
} as const;
