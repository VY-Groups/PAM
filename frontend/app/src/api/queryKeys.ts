/**
 * Query key factory (plan §3 `api/queryKeys.ts`).
 * Every cache key in the app starts here so invalidation stays greppable.
 */
export const queryKeys = {
  whoami: ['auth', 'whoami'] as const,
  health: ['health'] as const,
  overview: ['overview'] as const,
  events: (limit: number) => ['events', 'all', limit] as const,
  bypassStats: ['bypass', 'stats'] as const,
  bypassIncidents: (limit: number) => ['bypass', 'incidents', 'open', limit] as const,
} as const;
