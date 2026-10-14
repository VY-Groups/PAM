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
  // JIT Access screen (F4 screen 3): every query of the screen hangs off one
  // `['jit', ...]` root so a single prefix invalidation refreshes the queue,
  // the broker and the agent consoles together - they share rows (an agent
  // access request is also a JIT request).
  jitStats: ['jit', 'stats'] as const,
  jitQueue: (status: string, requester: string, limit: number) =>
    ['jit', 'queue', status, requester, limit] as const,
  jitRequest: (id: number | null) => ['jit', 'request', id] as const,
  brokerStats: ['jit', 'broker', 'stats'] as const,
  brokerPolicies: (limit: number) => ['jit', 'broker', 'policies', limit] as const,
  brokerCredentials: (limit: number) => ['jit', 'broker', 'credentials', limit] as const,
  agents: (limit: number) => ['jit', 'agents', limit] as const,
  agent: (id: number | null) => ['jit', 'agent', id] as const,
  agentAccessRequests: (limit: number) =>
    ['jit', 'agent-access', 'requests', limit] as const,
  agentAccessStats: ['jit', 'agent-access', 'stats'] as const,
  // Live Session Hub (F4 screen 4): one `['sessions', ...]` root so a single
  // prefix invalidation refreshes stats, the list, the detail, its recording
  // and the linked-grant governance facts together - they are views of the
  // same session row.
  sessionStats: ['sessions', 'stats'] as const,
  sessions: (limit: number) => ['sessions', 'list', limit] as const,
  sessionDetail: (id: number | null) => ['sessions', 'detail', id] as const,
  sessionEvents: (id: number | null) => ['sessions', 'events', id] as const,
  sessionGrant: (id: number | null) => ['sessions', 'grant', id] as const,
} as const;
