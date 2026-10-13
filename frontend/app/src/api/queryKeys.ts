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
  vaultStats: ['vault', 'stats'] as const,
  vaultItems: (limit: number) => ['vault', 'items', limit] as const,
  vaultItem: (id: number | null) => ['vault', 'item', id] as const,
  vaultEvents: (limit: number) => ['vault', 'events', limit] as const,
} as const;
