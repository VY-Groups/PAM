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
  // Policy & Zero Trust (F4 screen 5): one `['policy', ...]` root so a single
  // prefix invalidation refreshes the command-control posture, the rule
  // catalog, the approval queue, the incidents and every risk/UEBA view
  // together - they are views of the same policy engine.
  policyStats: ['policy', 'stats'] as const,
  policyRules: ['policy', 'rules'] as const,
  policyApprovals: ['policy', 'approvals'] as const,
  policyIncidents: (limit: number) => ['policy', 'incidents', limit] as const,
  riskStats: ['policy', 'risk', 'stats'] as const,
  riskEvaluations: (limit: number) => ['policy', 'risk', 'evaluations', limit] as const,
  riskBaselines: ['policy', 'risk', 'baselines'] as const,
  riskAnomalies: (limit: number) => ['policy', 'risk', 'anomalies', limit] as const,
  // Compliance & SOC2 (F4 screen 6): one `['compliance', ...]` root so a single
  // prefix invalidation refreshes the ledger digest, the hash-chain walk, the
  // unified trail and the connector chips together - they are views of the
  // same append-only ledger. The verify walk is an on-demand mutation, not a
  // cached read (it re-walks the whole chain server side).
  complianceStats: ['compliance', 'audit', 'stats'] as const,
  complianceEvents: (source: string, limit: number) =>
    ['compliance', 'events', source, limit] as const,
  complianceIntegrations: ['compliance', 'integrations'] as const,
  // Target Infrastructure (F4 screen 7): one `['infrastructure', ...]` root so
  // a single prefix invalidation refreshes the discovery aggregates, the
  // filtered target list, the accounts, the scans, the connector fleet and the
  // discovery event stream together - onboarding an asset moves all of them.
  // Filtered lists key on their server-side filter params, mirroring the
  // contract's own query contract.
  infraStats: ['infrastructure', 'discovery', 'stats'] as const,
  infraAssets: (pam: string, type: string, q: string) =>
    ['infrastructure', 'assets', pam, type, q] as const,
  infraAccounts: (limit: number) => ['infrastructure', 'accounts', limit] as const,
  infraScans: (limit: number) => ['infrastructure', 'scans', limit] as const,
  infraCloudStats: ['infrastructure', 'cloud', 'stats'] as const,
  infraConnectors: (provider: string, status: string) =>
    ['infrastructure', 'connectors', provider, status] as const,
  infraEvents: (limit: number) => ['infrastructure', 'events', limit] as const,
  // Vendor Access (F4 screen 8): one `['vendor', ...]` root so a single prefix
  // invalidation refreshes the registry, the selected dashboard, the scoped
  // request picker and the ITSM hint together - they are views of the same
  // third-party lifecycle. The registry keys on its server-side filter params
  // (status / q), mirroring the contract's own query contract; the KPI view
  // reads the unfiltered registry so its counts stay registry-wide.
  vendorList: (status: string, q: string) => ['vendor', 'list', status, q] as const,
  vendorDetail: (id: number | null) => ['vendor', 'detail', id] as const,
  vendorItems: ['vendor', 'items'] as const,
  vendorIntegrations: ['vendor', 'integrations'] as const,
  // Break-Glass (F4 screen 9): one `['breakGlass', ...]` root so a single
  // prefix invalidation refreshes the aggregates, the filtered request
  // list, the selected request's detail and the factor-state read
  // together - they are views of the same emergency lifecycle. The list
  // keys on its server-side status filter, mirroring the contract.
  breakGlassStats: ['breakGlass', 'stats'] as const,
  breakGlassList: (status: string) => ['breakGlass', 'list', status] as const,
  breakGlassDetail: (id: number | null) => ['breakGlass', 'detail', id] as const,
  breakGlassIntegrations: ['breakGlass', 'integrations'] as const,
  // Enterprise Licensing (F4 screen 10): one ['licensing', ...] root so a
  // single prefix invalidation refreshes the overview aggregates, the meta
  // catalog, the filtered registry, the selected license's detail and its
  // signed file together - they are views of the same license rows. The
  // list keys on its server-side filter params (status/tier/license_type/q),
  // mirroring the contract's own query contract.
  licensingOverview: ['licensing', 'overview'] as const,
  licensingMeta: ['licensing', 'meta'] as const,
  licensingList: (status: string, tier: string, licenseType: string, q: string) =>
    ['licensing', 'list', status, tier, licenseType, q] as const,
  licensingDetail: (key: string | null) => ['licensing', 'detail', key] as const,
  licensingFile: (key: string | null, format: string) =>
    ['licensing', 'file', key, format] as const,
  // System & Workflow Maps (ADR-0013, /topology): the live network view.
  // Read-only screen - no writes, so no invalidation fan-out.
  topologyCluster: ['topology', 'cluster'] as const,
  topologyIntegrations: ['topology', 'integrations'] as const,
  // Platform Settings (screen 11, ADR-0015): one ['settings', ...] root so
  // a single prefix invalidation refreshes the posture sections together -
  // they are views of the same running node. A settings group write (11.3)
  // invalidates this whole root: the POSTURE sections read the same node
  // state the group forms edit.
  settingsSso: ['settings', 'sso'] as const,
  settingsHsm: ['settings', 'hsm'] as const,
  settingsIntegrations: ['settings', 'integrations'] as const,
  settingsCluster: ['settings', 'cluster'] as const,
  settingsClusterBackups: ['settings', 'cluster', 'backups'] as const,
  // 11.2 RBAC/ABAC: the role directory and the binding table. The two
  // writes (grant / revoke) invalidate both - a grant can mint a token
  // and add a row, a revoke stamps `revoked_at` on one - so the tiles,
  // the summary line and the tables stay one view of the same registry.
  settingsRoles: ['settings', 'roles'] as const,
  settingsBindings: ['settings', 'bindings'] as const,
  // 11.4 identity specials: the sealed emergency admin's grant state. It
  // rides the settings root like the legacy `loadAll` does (a save re-read
  // refreshes it too) while keeping its own key so the open-request
  // mutation invalidates exactly this view.
  settingsEmergency: ['settings', 'emergency'] as const,
  // 11.3 group forms: the schema+values read (15 groups) and the config
  // changelog. A successful group PUT invalidates the settingsRoot
  // (values, posture lines and the changelog all move together).
  settingsRoot: ['settings'] as const,
  settingsGroups: ['settings', 'groups'] as const,
  settingsAudit: ['settings', 'audit'] as const,
  // Users & Credentials (ADR-0016 batch 11.7): one ['users', ...] root so a
  // single prefix invalidation refreshes the registry, the KPI tiles and
  // the derived status chips together - every write (create, patch active,
  // unlock, password reset, session revoke) moves the same rows. The list
  // keys on its server-side source filter, mirroring the contract.
  usersList: (source: string) => ['users', 'list', source] as const,
  usersRoot: ['users'] as const,
  // Security & MFA (ADR-0017 batch 11.8): one ['security', ...] root - a
  // factor write (enrol, verify, delete) or a backup-code regeneration
  // moves the same factor list, so every write invalidates securityFactors
  // and the table follows (the page orchestrates it around the step-up
  // retry-once flow).
  securityFactors: ['security', 'factors'] as const,
  securityRoot: ['security'] as const,
} as const;
