import { screen } from '@testing-library/react';
import { Outlet } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { WhoAmI, WhoAmIRole } from '../../api/generated/models';
import { expectNoAxeViolations } from '../../test/axe';
import { stubFetch, whoamiRoute } from '../../test/fetchMock';
import { renderWithRoutes } from '../../test/renderApp';
import { API_OPERATIONS } from '../../features/topology/topology.generated';
import { NAV_ITEMS } from '../layout/nav';
import { RequireAuth } from './RequireAuth';
import {
  ACTION_OPS,
  RoleGate,
  RoleLanding,
  canOperate,
  landingFor,
  visibleByRole,
} from './RoleGate';

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

/**
 * Operation subsets that drive every nav decision, verbatim from the
 * step-1 audit captures (`Temp/role-audit-raw.log`, 65 probes): the full
 * per-role lists are 48/13/34/31/145 operations, but only these strings
 * decide nav rows, and `nav.test.ts` pins each one to the OpenAPI list.
 */
const OPERATIONS: Record<string, string[]> = {
  operator: [
    'post /api/v1/vault/items/{item_id}/checkout',
    'post /api/v1/jit/requests',
    'post /api/v1/break-glass/requests',
    'post /api/v1/vendors/{vendor_id}/requests',
    'post /api/v1/sessions',
    'post /api/v1/discovery/assets',
    'post /api/v1/command-control/incidents/{incident_id}/close',
  ],
  approver: [
    'post /api/v1/jit/requests/{request_id}/approve',
    'post /api/v1/break-glass/requests/{request_id}/approve',
    'post /api/v1/vendors/{vendor_id}/approve',
    'post /api/v1/broker/credentials/{credential_id}/approve',
    'post /api/v1/sessions/{session_id}/events/{seq}/approve',
  ],
  auditor: [
    'get /api/v1/auth/report',
    'get /api/v1/cluster/export/sessions',
    'get /api/v1/cluster/export/vault',
    'get /api/v1/users',
    'get /api/v1/auth/sso/sessions',
    'get /api/v1/licenses/{license_key}/file',
  ],
  'auditor-read-only': [
    'get /api/v1/auth/report',
    'get /api/v1/users',
    'get /api/v1/auth/sso/sessions',
  ],
};

/** Honest whoami bodies (schema-required fields, directory-login posture). */
function whoamiFor(role: WhoAmIRole): WhoAmI {
  if (role === 'admin') {
    // Open/dev posture exactly as routes.py:644-652 builds it: operations
    // "all", operations_count = len(ADMIN_OPERATIONS) = 145 (printed gate).
    return {
      mode: 'open',
      principal: 'open',
      role: 'admin',
      kind: 'open',
      operations: 'all',
      operations_count: 145,
    };
  }
  const operations = OPERATIONS[role] ?? [];
  return {
    mode: 'token',
    principal: `aud-${role.replace('auditor-read-only', 'auditorro')}`,
    role,
    kind: 'ldap',
    operations,
    operations_count: operations.length,
  };
}

/**
 * The ADR-0021 Amendment 1 visibility table, restated as expected path
 * sets. Admin is the open-mode `'all'` body (real posture, routes.py
 * whoami); the four array-shaped roles are the audit's captures.
 */
const EXPECTED_VISIBLE: Record<WhoAmIRole, string[]> = {
  admin: NAV_ITEMS.map((item) => item.path),
  operator: [
    '/command-center',
    '/vault',
    '/jit',
    '/break-glass',
    '/vendor-access',
    '/sessions',
    '/infrastructure',
    '/policy',
    '/topology',
  ],
  approver: ['/approvals', '/command-center', '/topology'],
  auditor: [
    '/command-center',
    '/compliance',
    '/users',
    '/security',
    '/licensing',
    '/topology',
  ],
  'auditor-read-only': [
    '/command-center',
    '/compliance',
    '/users',
    '/security',
    '/topology',
  ],
};

const EXPECTED_LANDING: Record<WhoAmIRole, string> = {
  admin: '/command-center',
  operator: '/sessions',
  approver: '/approvals',
  auditor: '/compliance',
  'auditor-read-only': '/compliance',
};

describe('role visibility matrix (ADR-0021 D1/D5)', () => {
  for (const role of Object.keys(EXPECTED_VISIBLE) as WhoAmIRole[]) {
    it(`${role} sees exactly its nav rows`, () => {
      const whoami = whoamiFor(role);
      const visible = NAV_ITEMS.filter((item) => visibleByRole(item.path, whoami))
        .map((item) => item.path)
        .sort();
      expect(visible).toEqual([...EXPECTED_VISIBLE[role]].sort());
    });

    it(`${role} lands on ${EXPECTED_LANDING[role]}`, () => {
      expect(landingFor(whoamiFor(role))).toBe(EXPECTED_LANDING[role]);
    });
  }

  it("open mode 'all' shows every route", () => {
    const open: WhoAmI = {
      mode: 'open',
      principal: 'open',
      role: 'admin',
      kind: 'open',
      operations: 'all',
      operations_count: 145,
    };
    for (const item of NAV_ITEMS) expect(visibleByRole(item.path, open)).toBe(true);
    expect(landingFor(open)).toBe('/command-center');
  });

  it('unknown paths pass the gate (the 404 owns them)', () => {
    expect(visibleByRole('/nowhere', whoamiFor('approver'))).toBe(true);
  });
});

describe('RoleGate', () => {
  it('renders the friendly not-for-your-role page with a landing link', async () => {
    stubFetch([whoamiRoute(whoamiFor('approver'))]);
    const { container } = renderWithRoutes(
      [
        {
          path: '/vault',
          element: (
            <RoleGate>
              <p>secret vault content</p>
            </RoleGate>
          ),
        },
      ],
      '/vault',
    );
    expect(await screen.findByText('Not available for your role')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Go to my landing page' });
    expect(link).toHaveAttribute('href', '/approvals');
    expect(screen.queryByText('secret vault content')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('passes the content through for a role that holds the route operation', async () => {
    stubFetch([whoamiRoute(whoamiFor('operator'))]);
    renderWithRoutes(
      [
        {
          path: '/vault',
          element: (
            <RoleGate>
              <p>secret vault content</p>
            </RoleGate>
          ),
        },
      ],
      '/vault',
    );
    expect(await screen.findByText('secret vault content')).toBeInTheDocument();
    expect(screen.queryByText('Not available for your role')).not.toBeInTheDocument();
  });
});

/**
 * RoleLanding mirrors the real router: mounted under RequireAuth
 * (router.tsx:76), which resolves whoami before any child renders - so
 * the redirect always runs against a settled operations list.
 */
describe('RoleLanding', () => {
  const landingRoutes = [
    {
      // The real router's shape: RequireAuth wraps the shell layout, the
      // index child renders inside its Outlet (router.tsx:76-83).
      element: (
        <RequireAuth>
          <Outlet />
        </RequireAuth>
      ),
      children: [
        { index: true, element: <RoleLanding /> },
        { path: '/approvals', element: <p>inbox landing</p> },
        { path: '/compliance', element: <p>evidence landing</p> },
        { path: '/sessions', element: <p>sessions landing</p> },
        { path: '/command-center', element: <p>command landing</p> },
      ],
    },
  ];

  it('sends an approver to the inbox', async () => {
    stubFetch([whoamiRoute(whoamiFor('approver'))]);
    renderWithRoutes(landingRoutes, '/');
    expect(await screen.findByText('inbox landing')).toBeInTheDocument();
  });

  it('sends an auditor to the evidence view', async () => {
    stubFetch([whoamiRoute(whoamiFor('auditor'))]);
    renderWithRoutes(landingRoutes, '/');
    expect(await screen.findByText('evidence landing')).toBeInTheDocument();
  });

  it('sends an operator to live sessions', async () => {
    stubFetch([whoamiRoute(whoamiFor('operator'))]);
    renderWithRoutes(landingRoutes, '/');
    expect(await screen.findByText('sessions landing')).toBeInTheDocument();
  });

  it('sends admin to the Command Center', async () => {
    stubFetch([whoamiRoute(whoamiFor('admin'))]);
    renderWithRoutes(landingRoutes, '/');
    expect(await screen.findByText('command landing')).toBeInTheDocument();
  });
});

/**
 * D3's action gates must name real contract operations - same drift rule
 * as NAV_JOB_OPS: an invented string would fail open silently, a renamed
 * operation would never disable. `Temp/op_holders.py` additionally proves
 * each value's holders in ROLE_OPERATIONS/ADMIN_OPERATIONS (reason copy).
 */
describe('ACTION_OPS (step 6)', () => {
  it('every declared action is a case-insensitive member of API_OPERATIONS', () => {
    const api = new Set(API_OPERATIONS.map((op) => op.toLowerCase()));
    for (const [name, op] of Object.entries(ACTION_OPS)) {
      expect(api.has(op.toLowerCase()), `${name}: ${op}`).toBe(true);
    }
  });

  it('canOperate reads operations only: all, absent, present, unresolved', () => {
    expect(canOperate('post /api/v1/x', { operations: 'all' } as WhoAmI)).toBe(true);
    expect(canOperate('post /api/v1/x', { operations: ['post /api/v1/y'] } as WhoAmI)).toBe(
      false,
    );
    expect(canOperate('post /api/v1/x', { operations: ['post /api/v1/x'] } as WhoAmI)).toBe(
      true,
    );
    expect(canOperate('post /api/v1/x', null)).toBe(true);
  });
});
