import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useLocation } from 'react-router';

import type { WhoAmI } from '../../api/generated/models';
import { useAuth } from '../providers/useAuth';
import { NAV_JOB_OPS } from '../layout/nav';

/**
 * ADR-0021 (12.RC) role visibility: a route is visible when whoami's
 * contract-derived `operations` list satisfies the route's declared job
 * operations (any-of). No role names appear here or in nav.ts - the
 * server computes the operation list from ROLE_OPERATIONS, which CI pins
 * to the OpenAPI document (test_openapi_contract.py:133). `'all'` is the
 * open/dev posture: everything visible, as the server itself behaves.
 */
export function visibleByRole(path: string, whoami: WhoAmI | null): boolean {
  const required = NAV_JOB_OPS[path];
  if (required === undefined || required.length === 0) return true;
  const ops = whoami?.operations;
  if (ops === 'all') return true;
  // RequireAuth resolves whoami before the shell renders; null can only be
  // the transition frame, so fail open - the server still enforces every op.
  if (!Array.isArray(ops)) return true;
  return required.some((op) => ops.includes(op));
}

/**
 * The ordered operations rule for role landings (ADR-0021 Amendment 1) -
 * first match wins, still no role names: the setup/profile write is
 * admin-only in the contract, any approval op means the approver inbox,
 * auth/report means an auditor's evidence view, sessions-create means the
 * operator's day-2 console, everyone else lands on Command Center.
 */
export function landingFor(whoami: WhoAmI | null): string {
  const ops = whoami?.operations;
  const holds = (op: string): boolean =>
    ops === 'all' || (Array.isArray(ops) && ops.includes(op));
  if (holds('put /api/v1/setup/profile')) return '/command-center';
  if (NAV_JOB_OPS['/approvals'].some(holds)) return '/approvals';
  if (holds('get /api/v1/auth/report')) return '/compliance';
  if (holds('post /api/v1/sessions')) return '/sessions';
  return '/command-center';
}

/**
 * ADR-0021 D3 action gating: the operations behind every console action
 * that can render disabled. Pinned to the generated OpenAPI operation list
 * by RoleGate.test (same drift rule as NAV_JOB_OPS), and every value was
 * checked against backend `ROLE_OPERATIONS`/`ADMIN_OPERATIONS`
 * (Temp/op_holders.py) so the reason copy names a role that really holds
 * the operation. Deliberately absent: `get /api/v1/audit/export`,
 * `get /api/v1/audit/verify`, `post /api/v1/licenses/validate`,
 * `post /api/v1/command-control/evaluate` - no whoami (admin included)
 * lists them, so a client check could only disable buttons the server may
 * well allow; those stay enabled and the server's own refusal surfaces
 * verbatim (D3's second half; batch 12.RB adds read grants to gate them).
 */
export const ACTION_OPS = {
  jitApprove: 'post /api/v1/jit/requests/{request_id}/approve',
  jitDeny: 'post /api/v1/jit/requests/{request_id}/deny',
  breakGlassApprove: 'post /api/v1/break-glass/requests/{request_id}/approve',
  breakGlassDeny: 'post /api/v1/break-glass/requests/{request_id}/deny',
  vendorApprove: 'post /api/v1/vendors/{vendor_id}/approve',
  vendorDeny: 'post /api/v1/vendors/{vendor_id}/deny',
  brokerApprove: 'post /api/v1/broker/credentials/{credential_id}/approve',
  brokerDeny: 'post /api/v1/broker/credentials/{credential_id}/deny',
  eventApprove: 'post /api/v1/sessions/{session_id}/events/{seq}/approve',
  eventDeny: 'post /api/v1/sessions/{session_id}/events/{seq}/deny',
  userCreate: 'post /api/v1/users',
  userUpdate: 'patch /api/v1/users/{user_id}',
  userUnlock: 'post /api/v1/users/{user_id}/unlock',
  userPasswordReset: 'post /api/v1/users/{user_id}/password-reset',
  userSessionsRevoke: 'delete /api/v1/users/{user_id}/sessions',
  bindingCreate: 'post /api/v1/role-bindings',
  bindingRevoke: 'delete /api/v1/role-bindings/{binding_id}',
  agentCreate: 'post /api/v1/agents',
  agentUpdate: 'patch /api/v1/agents/{agent_id}',
  agentRevoke: 'delete /api/v1/agents/{agent_id}',
  agentTaskCreate: 'post /api/v1/agents/{agent_id}/tasks',
  brokerPolicyCreate: 'post /api/v1/broker/policies',
  brokerPolicyDelete: 'delete /api/v1/broker/policies/{policy_id}',
  licenseImport: 'post /api/v1/licenses/import',
  licenseRevoke: 'post /api/v1/licenses/{license_key}/revoke',
  licenseRestore: 'post /api/v1/licenses/{license_key}/restore',
  connectorCreate: 'post /api/v1/cloud/connectors',
  connectorTest: 'post /api/v1/cloud/connectors/{connector_id}/test',
  connectorDelete: 'delete /api/v1/cloud/connectors/{connector_id}',
  ruleCreate: 'post /api/v1/command-control/rules',
  ruleUpdate: 'put /api/v1/command-control/rules/{rule_id}',
  ruleDelete: 'delete /api/v1/command-control/rules/{rule_id}',
  vendorCreate: 'post /api/v1/vendors',
  vendorNda: 'post /api/v1/vendors/{vendor_id}/nda',
  vendorMfa: 'post /api/v1/vendors/{vendor_id}/mfa',
  vendorTicket: 'post /api/v1/vendors/{vendor_id}/ticket',
  vendorRevoke: 'post /api/v1/vendors/{vendor_id}/revoke',
} as const;

/** D3: may this session exercise `op`? Same fail-open rule as the route gate. */
export function canOperate(op: string, whoami: WhoAmI | null): boolean {
  const ops = whoami?.operations;
  if (ops === 'all') return true;
  // RequireAuth resolves whoami before the shell renders; null can only be
  // the transition frame, so fail open - the server still enforces every op.
  if (!Array.isArray(ops)) return true;
  return ops.includes(op);
}

/** Route wrapper: a hidden route renders the friendly not-for-your-role page. */
export function RoleGate({ children }: { children: ReactNode }) {
  const { whoami } = useAuth();
  const { pathname } = useLocation();
  const { t } = useTranslation();

  if (visibleByRole(pathname, whoami)) return <>{children}</>;
  return (
    <div className="p-space-xl max-w-2xl mx-auto">
      <h1 className="font-title-lg text-title-lg text-on-surface">{t('roleGate.title')}</h1>
      <p className="mt-space-sm font-body-md text-body-md text-on-surface-variant">
        {t('roleGate.body', { role: whoami?.role ?? '' })}
      </p>
      <Link
        to={landingFor(whoami)}
        className="inline-block mt-space-md px-space-md py-space-sm rounded-lg bg-primary-container text-on-primary-container font-label-md text-label-md font-semibold shadow-sm"
      >
        {t('roleGate.landing')}
      </Link>
    </div>
  );
}

/** Index route: send each session to its role's landing page. */
export function RoleLanding() {
  const { whoami } = useAuth();
  return <Navigate to={landingFor(whoami)} replace />;
}
