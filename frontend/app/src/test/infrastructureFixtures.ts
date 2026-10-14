/**
 * F4 screen 7 (Target Infrastructure) test fixtures - VERBATIM rig
 * captures, generated from the Docker rig responses saved in
 * Temp/opencode/cap7/ (scratch directory, never staged) on the :5100 open
 * rig. Every value - scan counters, asset rows, probe timings, the 409
 * discover refusal, connector lifecycle messages, event rows - is
 * byte-for-byte what the license server returned. The write captures were
 * produced against the dev rig with synthetic vypam- probe strings
 * (screen 5 policy precedent): the scan really probed 127.0.0.1:22,443,
 * the probe really hit a closed loopback port, and the cloud connector
 * was deleted again (CONNECTOR_DELETE_RESPONSE is its real teardown).
 *
 * Two clearly-labelled SYNTHETIC additions (schema-valid states the
 * rig does not produce, same rule as the contract-shaped error bodies
 * used elsewhere): ASSETS_EMPTY_RESPONSE proves the honest empty
 * discovery list, and ASSETS_WITH_UNMANAGED_RESPONSE re-plays the
 * unmanaged state this rig really produced once (see below) so the
 * adopt path stays covered.
 */
export const DISCOVERY_STATS_RESPONSE = {
  status: 200,
  body: {
    accounts_total: 3,
    by_pam_status: {
      ignored: 1,
      managed: 2,
      unmanaged: 0,
    },
    by_risk: {
      CRITICAL: 1,
      HIGH: 2,
      LOW: 0,
      MEDIUM: 0,
    },
    by_type: {
      aix: 0,
      cloud: 0,
      database: 1,
      docker: 0,
      firewall: 0,
      hyperv: 0,
      kubernetes: 0,
      linux: 2,
      loadbalancer: 0,
      network: 0,
      solaris: 0,
      unix: 0,
      unknown: 0,
      vmware: 0,
      windows: 0,
    },
    scans: {
      last: {
        error: '',
        findings: 0,
        finished_at: '2026-10-14T21:56:44.651686',
        hosts_open: 0,
        hosts_probed: 1,
        id: 1,
        method: 'tcp_probe',
        ports: [22, 443],
        scope: '127.0.0.1',
        services_found: 0,
        started_at: '2026-10-14T21:56:44.571429',
        status: 'completed',
        triggered_by: 'open',
      },
      total: 1,
    },
    total: 3,
  },
};

export const ASSETS_LIST_RESPONSE = {
  status: 200,
  body: {
    assets: [
      {
        address: 'vypam-probe-b.test',
        asset_type: 'database',
        detail: '',
        first_seen: '2026-10-14T21:56:45.158648',
        hostname: '',
        id: 3,
        last_seen: '2026-10-14T21:56:45.158653',
        method: 'manual',
        notes: '',
        pam_status: 'managed',
        ports: [],
        recommended_policy: 'JIT checkout + 24h credential rotation + session recording',
        risk: 'CRITICAL',
        source: 'manual',
        vault_count: 2,
      },
      {
        address: '10.99.8.42',
        asset_type: 'linux',
        detail: '',
        first_seen: '2026-10-14T20:37:26.772258',
        hostname: 'gate-8a.lab',
        id: 1,
        last_seen: '2026-10-14T20:37:26.772262',
        method: 'manual',
        notes: '',
        pam_status: 'ignored',
        ports: [],
        recommended_policy: 'SSH certificate JIT + 24h credential rotation',
        risk: 'HIGH',
        source: 'manual',
        vault_count: 1,
      },
      {
        address: 'vypam-probe-a.test',
        asset_type: 'linux',
        detail: '',
        first_seen: '2026-10-14T21:56:44.756555',
        hostname: 'vypam-probe-a',
        id: 2,
        last_seen: '2026-10-14T21:56:44.756564',
        method: 'manual',
        notes: 'vypam synthetic capture probe',
        pam_status: 'managed',
        ports: [],
        recommended_policy: 'SSH certificate JIT + 24h credential rotation',
        risk: 'HIGH',
        source: 'manual',
        vault_count: 1,
      },
    ],
    limit: 200,
    offset: 0,
    total: 3,
  },
};

export const ACCOUNTS_LIST_RESPONSE = {
  status: 200,
  body: {
    accounts: [
      {
        asset_address: '10.99.8.42',
        asset_id: 1,
        created_at: '2026-10-14T20:37:26.859672',
        id: 1,
        kind: 'builtin_admin',
        source: 'manual',
        username: 'root',
      },
      {
        asset_address: 'vypam-probe-a.test',
        asset_id: 2,
        created_at: '2026-10-14T21:56:44.840080',
        id: 2,
        kind: 'other',
        source: 'manual',
        username: 'vypam-probe-admin',
      },
      {
        asset_address: 'vypam-probe-b.test',
        asset_id: 3,
        created_at: '2026-10-14T21:56:45.232715',
        id: 3,
        kind: 'other',
        source: 'manual',
        username: 'vypam-probe-db',
      },
    ],
    limit: 200,
    offset: 0,
    total: 3,
  },
};

export const SCANS_LIST_RESPONSE = {
  status: 200,
  body: {
    limit: 50,
    scans: [
      {
        error: '',
        findings: 0,
        finished_at: '2026-10-14T21:56:44.651686',
        hosts_open: 0,
        hosts_probed: 1,
        id: 1,
        method: 'tcp_probe',
        ports: [22, 443],
        scope: '127.0.0.1',
        services_found: 0,
        started_at: '2026-10-14T21:56:44.571429',
        status: 'completed',
        triggered_by: 'open',
      },
    ],
    total: 1,
  },
};

export const CLOUD_STATS_RESPONSE = {
  status: 200,
  body: {
    by_provider: {
      aws: {
        configured: 0,
        connected: 0,
        error: 0,
        'not connected': 0,
        total: 0,
      },
      azure: {
        configured: 0,
        connected: 0,
        error: 0,
        'not connected': 0,
        total: 0,
      },
      gcp: {
        configured: 0,
        connected: 0,
        error: 0,
        'not connected': 0,
        total: 0,
      },
      kubernetes: {
        configured: 0,
        connected: 0,
        error: 1,
        'not connected': 0,
        total: 1,
      },
    },
    by_status: {
      configured: 0,
      connected: 0,
      error: 1,
      'not connected': 0,
    },
    connectors: 1,
    discovered_assets: 0,
    events: 3,
    rbac_grants: {
      active: 0,
      approved: 0,
      blocked: 0,
      closed: 0,
      denied: 0,
      expired: 0,
      open: 0,
      pending: 0,
      total: 0,
    },
  },
};

export const CONNECTORS_LIST_RESPONSE = {
  status: 200,
  body: {
    connectors: [
      {
        account_ref: 'vypam-probe-account-2',
        created_at: '2026-10-14T21:56:45.586312',
        created_by: 'open',
        credential_item_id: null,
        endpoint: 'http://127.0.0.1:9/v1',
        id: 1,
        last_test_at: '2026-10-14T21:56:45.796343',
        last_test_detail: 'connection failed: [Errno 111] Connection refused (0 ms)',
        name: 'vypam-probe-conn',
        provider: 'kubernetes',
        regions: [],
        services: [],
        status: 'error',
      },
    ],
    limit: 200,
    offset: 0,
    total: 1,
  },
};

export const CONNECTORS_EMPTY_RESPONSE = {
  status: 200,
  body: {
    connectors: [],
    limit: 200,
    offset: 0,
    total: 0,
  },
};

export const DISCOVERY_EVENTS_RESPONSE = {
  status: 200,
  body: {
    events: [
      {
        action: 'asset_onboarded',
        actor: 'open',
        created_at: '2026-10-14T21:56:45.495776',
        detail: {
          adopted: true,
          asset_type: 'database',
          principal: 'vypam-probe-db',
          risk: 'CRITICAL',
          vault_item_id: 4,
        },
        event_hash: 'c27378e6d3792064c3b7757951e6d11e654ec1498ff4553241c8ab9203d8eaa7',
        id: 'discovery:10',
        seq: 80,
        source: 'discovery',
        subject: 'vypam-probe-b.test',
      },
      {
        action: 'asset_updated',
        actor: 'open',
        created_at: '2026-10-14T21:56:45.336217',
        detail: {
          changes: {
            pam_status: {
              from: 'managed',
              to: 'unmanaged',
            },
          },
        },
        event_hash: 'aa8a9e739984410d33e12361f7436ca48a05bbcaa56824ad81bbb85273b78e74',
        id: 'discovery:9',
        seq: 78,
        source: 'discovery',
        subject: 'vypam-probe-b.test',
      },
      {
        action: 'asset_onboarded',
        actor: 'open',
        created_at: '2026-10-14T21:56:45.243904',
        detail: {
          asset_type: 'database',
          principal: 'vypam-probe-db',
          risk: 'CRITICAL',
          vault_item_id: 3,
        },
        event_hash: '5afeb5875d878c730b9f89fcda501e68e184fc59fb02de6e731428dad874bb66',
        id: 'discovery:8',
        seq: 77,
        source: 'discovery',
        subject: 'vypam-probe-b.test',
      },
      {
        action: 'asset_updated',
        actor: 'open',
        created_at: '2026-10-14T21:56:45.070350',
        detail: {
          changes: {
            pam_status: {
              from: 'ignored',
              to: 'managed',
            },
          },
        },
        event_hash: '1c469b04dfc28093940f441f6d2099083bd1a3669a6505c8db12e7ebb9749499',
        id: 'discovery:7',
        seq: 75,
        source: 'discovery',
        subject: 'vypam-probe-a.test',
      },
      {
        action: 'asset_updated',
        actor: 'open',
        created_at: '2026-10-14T21:56:44.930466',
        detail: {
          changes: {
            pam_status: {
              from: 'managed',
              to: 'ignored',
            },
          },
        },
        event_hash: '72021f52de17123401328ea72ed870b0444cb6153ea6108fba2b8b42837a02e1',
        id: 'discovery:6',
        seq: 74,
        source: 'discovery',
        subject: 'vypam-probe-a.test',
      },
      {
        action: 'asset_onboarded',
        actor: 'open',
        created_at: '2026-10-14T21:56:44.854060',
        detail: {
          asset_type: 'linux',
          principal: 'vypam-probe-admin',
          risk: 'HIGH',
          vault_item_id: 2,
        },
        event_hash: '96cedca98453017a5d64a96f02bd006eed7500935beed6e89d6eb2901387c140',
        id: 'discovery:5',
        seq: 73,
        source: 'discovery',
        subject: 'vypam-probe-a.test',
      },
      {
        action: 'scan_completed',
        actor: 'open',
        created_at: '2026-10-14T21:56:44.670853',
        detail: {
          findings: 0,
          hosts_open: 0,
          hosts_probed: 1,
          services_found: 0,
        },
        event_hash: '47950aa793f7dde278e96a979580e74b05a7714e79352e137ab8df43ee6d7727',
        id: 'discovery:4',
        seq: 71,
        source: 'discovery',
        subject: '127.0.0.1',
      },
      {
        action: 'scan_started',
        actor: 'open',
        created_at: '2026-10-14T21:56:44.586671',
        detail: {
          hosts: 1,
          ports: [22, 443],
        },
        event_hash: 'f07d5de0908fdb2199e3c2fef96e8cf4bb63bf35572b6f694ba1eab22fcd3171',
        id: 'discovery:3',
        seq: 70,
        source: 'discovery',
        subject: '127.0.0.1',
      },
      {
        action: 'asset_updated',
        actor: 'gate',
        created_at: '2026-10-14T20:37:30.756782',
        detail: {
          changes: {
            pam_status: {
              from: 'managed',
              to: 'ignored',
            },
          },
        },
        event_hash: '48ae02d525470fbdd1fea23b43e6e909615613725e16ff387163066f0c185a17',
        id: 'discovery:2',
        seq: 33,
        source: 'discovery',
        subject: '10.99.8.42',
      },
      {
        action: 'asset_onboarded',
        actor: 'gate',
        created_at: '2026-10-14T20:37:26.874680',
        detail: {
          asset_type: 'linux',
          principal: 'root',
          risk: 'HIGH',
          vault_item_id: 1,
        },
        event_hash: 'f2ffbf7bf8199f3024b114227f099c63ac809b14a49061b9d1badcc2709a33a0',
        id: 'discovery:1',
        seq: 13,
        source: 'discovery',
        subject: '10.99.8.42',
      },
    ],
    limit: 20,
    source: 'discovery',
    total: 10,
  },
};

export const SCAN_CREATE_RESPONSE = {
  status: 200,
  body: {
    message: 'Scan finished: 0/1 hosts open, 0 new asset(s)',
    scan: {
      error: '',
      findings: 0,
      finished_at: '2026-10-14T21:56:44.651686',
      hosts_open: 0,
      hosts_probed: 1,
      id: 1,
      method: 'tcp_probe',
      ports: [22, 443],
      scope: '127.0.0.1',
      services_found: 0,
      started_at: '2026-10-14T21:56:44.571429',
      status: 'completed',
      triggered_by: 'open',
    },
  },
};

export const ASSET_CREATE_RESPONSE = {
  status: 200,
  body: {
    asset: {
      address: 'vypam-probe-a.test',
      asset_type: 'linux',
      detail: '',
      first_seen: '2026-10-14T21:56:44.756555',
      hostname: 'vypam-probe-a',
      id: 2,
      last_seen: '2026-10-14T21:56:44.756564',
      method: 'manual',
      notes: 'vypam synthetic capture probe',
      pam_status: 'managed',
      ports: [],
      recommended_policy: 'SSH certificate JIT + 24h credential rotation',
      risk: 'HIGH',
      source: 'manual',
    },
    message: 'Target onboarded',
    vault_item: {
      access_tier: 'Tier-2',
      auth_method: 'Password',
      checked_out_at: null,
      checked_out_by: null,
      created_at: '2026-10-14T21:56:44.782375',
      description: 'Admin credential for vypam-probe-a',
      id: 2,
      last_rotated_at: '2026-10-14T21:56:44.782037',
      name: 'vypam-probe-a vypam-probe-admin',
      principal: 'vypam-probe-admin',
      rotation_hours_remaining: 23,
      rotation_interval_hours: 24,
      rotation_interval_label: 'Every 1d',
      secret_type: 'ssh_key',
      secret_updated_at: '2026-10-14T21:56:44.803344',
      secret_version: 1,
      status: 'available',
      target: 'vypam-probe-a.test',
      target_detail: 'vypam-probe-a',
    },
  },
};

export const ASSET_IGNORE_RESPONSE = {
  status: 200,
  body: {
    asset: {
      address: 'vypam-probe-a.test',
      asset_type: 'linux',
      detail: '',
      first_seen: '2026-10-14T21:56:44.756555',
      hostname: 'vypam-probe-a',
      id: 2,
      last_seen: '2026-10-14T21:56:44.756564',
      method: 'manual',
      notes: 'vypam synthetic capture probe',
      pam_status: 'ignored',
      ports: [],
      recommended_policy: 'SSH certificate JIT + 24h credential rotation',
      risk: 'HIGH',
      source: 'manual',
    },
    message: 'Asset updated',
  },
};

export const ASSET_RESTORE_RESPONSE = {
  status: 200,
  body: {
    asset: {
      address: 'vypam-probe-a.test',
      asset_type: 'linux',
      detail: '',
      first_seen: '2026-10-14T21:56:44.756555',
      hostname: 'vypam-probe-a',
      id: 2,
      last_seen: '2026-10-14T21:56:44.756564',
      method: 'manual',
      notes: 'vypam synthetic capture probe',
      pam_status: 'managed',
      ports: [],
      recommended_policy: 'SSH certificate JIT + 24h credential rotation',
      risk: 'HIGH',
      source: 'manual',
    },
    message: 'Asset updated',
  },
};

export const ASSET_UNMANAGED_RESPONSE = {
  status: 200,
  body: {
    asset: {
      address: 'vypam-probe-b.test',
      asset_type: 'database',
      detail: '',
      first_seen: '2026-10-14T21:56:45.158648',
      hostname: '',
      id: 3,
      last_seen: '2026-10-14T21:56:45.158653',
      method: 'manual',
      notes: '',
      pam_status: 'unmanaged',
      ports: [],
      recommended_policy: 'JIT checkout + 24h credential rotation + session recording',
      risk: 'CRITICAL',
      source: 'manual',
    },
    message: 'Asset updated',
  },
};

export const ASSET_ADOPT_RESPONSE = {
  status: 200,
  body: {
    asset: {
      address: 'vypam-probe-b.test',
      asset_type: 'database',
      detail: '',
      first_seen: '2026-10-14T21:56:45.158648',
      hostname: '',
      id: 3,
      last_seen: '2026-10-14T21:56:45.158653',
      method: 'manual',
      notes: '',
      pam_status: 'managed',
      ports: [],
      recommended_policy: 'JIT checkout + 24h credential rotation + session recording',
      risk: 'CRITICAL',
      source: 'manual',
    },
    message: 'Target onboarded',
    vault_item: {
      access_tier: 'Tier-2',
      auth_method: 'Password',
      checked_out_at: null,
      checked_out_by: null,
      created_at: '2026-10-14T21:56:45.447567',
      description: 'Admin credential for vypam-probe-b.test',
      id: 4,
      last_rotated_at: '2026-10-14T21:56:45.447228',
      name: 'vypam-probe-b.test vypam-probe-db #3',
      principal: 'vypam-probe-db',
      rotation_hours_remaining: 23,
      rotation_interval_hours: 24,
      rotation_interval_label: 'Every 1d',
      secret_type: 'database',
      secret_updated_at: '2026-10-14T21:56:45.462740',
      secret_version: 1,
      status: 'available',
      target: 'vypam-probe-b.test',
      target_detail: '',
    },
  },
};

export const CONNECTOR_CREATE_RESPONSE = {
  status: 200,
  body: {
    connector: {
      account_ref: 'vypam-probe-account',
      created_at: '2026-10-14T21:56:45.586312',
      created_by: 'open',
      credential_item_id: null,
      endpoint: 'http://127.0.0.1:9/v1',
      id: 1,
      last_test_at: null,
      last_test_detail: '',
      name: 'vypam-probe-conn',
      provider: 'kubernetes',
      regions: [],
      services: [],
      status: 'configured',
    },
    message: 'Cloud connector vypam-probe-conn registered (kubernetes, configured)',
  },
};

export const CONNECTOR_PATCH_RESPONSE = {
  status: 200,
  body: {
    connector: {
      account_ref: 'vypam-probe-account-2',
      created_at: '2026-10-14T21:56:45.586312',
      created_by: 'open',
      credential_item_id: null,
      endpoint: 'http://127.0.0.1:9/v1',
      id: 1,
      last_test_at: null,
      last_test_detail: '',
      name: 'vypam-probe-conn',
      provider: 'kubernetes',
      regions: [],
      services: [],
      status: 'configured',
    },
    message: 'Cloud connector vypam-probe-conn updated',
  },
};

export const PROBE_RESPONSE = {
  status: 200,
  body: {
    connector: {
      account_ref: 'vypam-probe-account-2',
      created_at: '2026-10-14T21:56:45.586312',
      created_by: 'open',
      credential_item_id: null,
      endpoint: 'http://127.0.0.1:9/v1',
      id: 1,
      last_test_at: '2026-10-14T21:56:45.796343',
      last_test_detail: 'connection failed: [Errno 111] Connection refused (0 ms)',
      name: 'vypam-probe-conn',
      provider: 'kubernetes',
      regions: [],
      services: [],
      status: 'error',
    },
    message:
      'vypam-probe-conn probe failed: connection failed: [Errno 111] Connection refused',
    probe: {
      checked_at: '2026-10-14T21:56:45.796343',
      detail: 'connection failed: [Errno 111] Connection refused',
      elapsed_ms: 0,
      http_status: null,
      ok: false,
    },
  },
};

export const CONNECTOR_DELETE_RESPONSE = {
  status: 200,
  body: {
    connector: {
      account_ref: 'vypam-probe-account-2',
      created_at: '2026-10-14T21:56:45.586312',
      created_by: 'open',
      credential_item_id: null,
      endpoint: 'http://127.0.0.1:9/v1',
      id: 1,
      last_test_at: '2026-10-14T21:56:45.796343',
      last_test_detail: 'connection failed: [Errno 111] Connection refused (0 ms)',
      name: 'vypam-probe-conn',
      provider: 'kubernetes',
      regions: [],
      services: [],
      status: 'error',
    },
    deleted: true,
    id: 1,
    message: 'Cloud connector vypam-probe-conn removed',
  },
};
export const DISCOVER_REFUSED_RESPONSE = {
  status: 409,
  body: {
    details: {
      configured: false,
      field: 'credential',
    },
    error: 'Cloud connector credential is not configured',
  },
};

/** SYNTHETIC (labelled): schema-valid empty discovery list - the rig's
 * seeded gate asset keeps every real capture non-empty. */
export const ASSETS_EMPTY_RESPONSE = {
  status: 200,
  body: {
    assets: [],
    total: 0,
    limit: 200,
    offset: 0,
  },
};

/**
 * SYNTHETIC (labelled): the verbatim asset list with probe-b (id 3)
 * dropped back to `unmanaged` - a state the rig really produced once
 * (the w_asset_b_unmanaged capture) before the adopt capture moved it
 * forward again, so the fixture set also covers the adopt path.
 */
export const ASSETS_WITH_UNMANAGED_RESPONSE = {
  status: 200,
  body: {
    ...ASSETS_LIST_RESPONSE.body,
    assets: ASSETS_LIST_RESPONSE.body.assets.map((a) =>
      a.id === 3 ? { ...a, pam_status: 'unmanaged' as const } : a,
    ),
  },
};

/** The ids/counts/messages the screen tests lean on (from the captures above). */
export const INFRA_FACTS = {
  assetsTotal: 3,
  accountsTotal: 3,
  scansTotal: 1,
  connectorsTotal: 1,
  eventsTotal: 10,
  eventsLen: 10,
  byTypeLinux: 2,
  byTypeDatabase: 1,
  byRiskCritical: 1,
  pamManaged: 2,
  pamIgnored: 1,
  gateAssetId: 1,
  gateAssetAddr: '10.99.8.42',
  probeAssetId: 2,
  probeAssetAddr: 'vypam-probe-a.test',
  scanScope: '127.0.0.1',
  scanMessage: 'Scan finished: 0/1 hosts open, 0 new asset(s)',
  connectorId: 1,
  connectorName: 'vypam-probe-conn',
  connectorStatus: 'error',
  probeDetail: 'connection failed: [Errno 111] Connection refused (0 ms)',
  probeMessage:
    'vypam-probe-conn probe failed: connection failed: [Errno 111] Connection refused',
  cloudConnectors: 1,
  cloudKubeError: 1,
  firstEventAction: 'asset_onboarded',
  firstEventSeq: 80,
  lastEventSeq: 13,
  totalAssetsNote: 'three assets: gate-8a.lab + the two vypam- capture probes',
};
