/**
 * The five application-workflow diagrams (ADR-0013, /topology view 5).
 *
 * Curated - a workflow is a human claim about which contract operations
 * form a real lifecycle - and gated: every `operation` must exist in
 * `apis/openapi.yaml` and every evidence reference must exist on disk
 * with its stated marker text. `topology.generated.test.ts` asserts
 * both against independently parsed sources, so this file cannot
 * describe a flow the product does not implement.
 *
 * Evidence is the repo's own proof artifacts: verbatim rig-capture
 * fixtures (the bodies the server really answered) and the test/gate
 * names that drive each step live.
 */
export interface WorkflowStep {
  /** "POST /api/v1/licenses/import" - validated against the contract. */
  operation: string;
  /** i18n key: what this step is. */
  labelKey: string;
  /** i18n key: honest outcome or refusal note rendered under the step. */
  noteKey?: string;
  /** Repo-relative proof file + the marker text it must contain. */
  evidence: { file: string; contains: string };
}

export interface Workflow {
  id: string;
  titleKey: string;
  subtitleKey: string;
  steps: WorkflowStep[];
}

const LIC_FIXTURES = 'frontend/app/src/test/licensingFixtures.ts';
const BG_FIXTURES = 'frontend/app/src/test/breakGlassFixtures.ts';
const VENDOR_FIXTURES = 'frontend/app/src/test/vendorFixtures.ts';
const JIT_FIXTURES = 'frontend/app/src/test/jitFixtures.ts';
const GATE = 'shots_tool/__verify_agent.mjs';

export const WORKFLOWS: Workflow[] = [
  {
    id: 'license',
    titleKey: 'topology.workflows.license.title',
    subtitleKey: 'topology.workflows.license.subtitle',
    steps: [
      {
        operation: 'GET /api/v1/licenses',
        labelKey: 'topology.workflows.license.s1',
        evidence: { file: LIC_FIXTURES, contains: 'LIC_LIST_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/licenses/import',
        labelKey: 'topology.workflows.license.s2',
        noteKey: 'topology.workflows.license.s2n',
        evidence: { file: LIC_FIXTURES, contains: 'LIC_IMPORT_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/licenses/import',
        labelKey: 'topology.workflows.license.s3',
        noteKey: 'topology.workflows.license.s3n',
        evidence: { file: LIC_FIXTURES, contains: 'is already installed' },
      },
      {
        operation: 'POST /api/v1/licenses/validate',
        labelKey: 'topology.workflows.license.s4',
        noteKey: 'topology.workflows.license.s4n',
        evidence: { file: LIC_FIXTURES, contains: 'LIC_VALIDATE_ACTIVE_RESPONSE' },
      },
      {
        operation: 'GET /api/v1/licenses/{license_key}/file',
        labelKey: 'topology.workflows.license.s5',
        evidence: { file: LIC_FIXTURES, contains: 'LIC_FILE_JWT_ACTIVE_TEXT' },
      },
      {
        operation: 'POST /api/v1/licenses/{license_key}/revoke',
        labelKey: 'topology.workflows.license.s6',
        noteKey: 'topology.workflows.license.s6n',
        evidence: { file: LIC_FIXTURES, contains: 'License revoked' },
      },
      {
        operation: 'POST /api/v1/licenses/{license_key}/restore',
        labelKey: 'topology.workflows.license.s7',
        noteKey: 'topology.workflows.license.s7n',
        evidence: { file: LIC_FIXTURES, contains: 'License restored' },
      },
    ],
  },
  {
    id: 'breakGlass',
    titleKey: 'topology.workflows.breakGlass.title',
    subtitleKey: 'topology.workflows.breakGlass.subtitle',
    steps: [
      {
        operation: 'POST /api/v1/break-glass/requests',
        labelKey: 'topology.workflows.breakGlass.s1',
        evidence: { file: BG_FIXTURES, contains: 'BG_FILE_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/break-glass/requests/{request_id}/approve',
        labelKey: 'topology.workflows.breakGlass.s2',
        noteKey: 'topology.workflows.breakGlass.s2n',
        evidence: { file: BG_FIXTURES, contains: 'BG_SELF_APPROVE_403' },
      },
      {
        operation: 'POST /api/v1/break-glass/requests/{request_id}/approve',
        labelKey: 'topology.workflows.breakGlass.s3',
        noteKey: 'topology.workflows.breakGlass.s3n',
        evidence: { file: BG_FIXTURES, contains: 'BG_DUPLICATE_APPROVER_400' },
      },
      {
        operation: 'POST /api/v1/break-glass/requests/{request_id}/open',
        labelKey: 'topology.workflows.breakGlass.s4',
        noteKey: 'topology.workflows.breakGlass.s4n',
        evidence: { file: BG_FIXTURES, contains: 'BG_OPEN_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/break-glass/requests/{request_id}/close',
        labelKey: 'topology.workflows.breakGlass.s5',
        noteKey: 'topology.workflows.breakGlass.s5n',
        evidence: { file: BG_FIXTURES, contains: 'BG_CLOSE_RESPONSE' },
      },
    ],
  },
  {
    id: 'auth',
    titleKey: 'topology.workflows.auth.title',
    subtitleKey: 'topology.workflows.auth.subtitle',
    steps: [
      {
        operation: 'POST /api/v1/auth/login',
        labelKey: 'topology.workflows.auth.s1',
        evidence: {
          file: 'frontend/app/src/features/auth/pages/LoginPage.test.tsx',
          contains: 'logs in with valid credentials',
        },
      },
      {
        operation: 'GET /api/v1/auth/whoami',
        labelKey: 'topology.workflows.auth.s2',
        evidence: {
          file: 'frontend/app/src/app/layout/AppShell.test.tsx',
          contains: 'renders the honest whoami identity chip',
        },
      },
      {
        operation: 'POST /api/v1/role-bindings',
        labelKey: 'topology.workflows.auth.s3',
        noteKey: 'topology.workflows.auth.s3n',
        evidence: { file: GATE, contains: 'RBAC flow: operator binding grants' },
      },
      {
        operation: 'GET /api/v1/roles',
        labelKey: 'topology.workflows.auth.s4',
        noteKey: 'topology.workflows.auth.s4n',
        evidence: { file: GATE, contains: 'may not call GET /api/v1/roles' },
      },
      {
        operation: 'DELETE /api/v1/role-bindings/{binding_id}',
        labelKey: 'topology.workflows.auth.s5',
        noteKey: 'topology.workflows.auth.s5n',
        evidence: { file: GATE, contains: 'the revoked token stops working immediately' },
      },
    ],
  },
  {
    id: 'vendor',
    titleKey: 'topology.workflows.vendor.title',
    subtitleKey: 'topology.workflows.vendor.subtitle',
    steps: [
      {
        operation: 'POST /api/v1/vendors',
        labelKey: 'topology.workflows.vendor.s1',
        evidence: { file: VENDOR_FIXTURES, contains: 'INVITE_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/vendors/{vendor_id}/mfa',
        labelKey: 'topology.workflows.vendor.s2',
        noteKey: 'topology.workflows.vendor.s2n',
        evidence: { file: VENDOR_FIXTURES, contains: 'MFA_WRONG_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/vendors/{vendor_id}/nda',
        labelKey: 'topology.workflows.vendor.s3',
        evidence: { file: VENDOR_FIXTURES, contains: 'NDA_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/vendors/{vendor_id}/ticket',
        labelKey: 'topology.workflows.vendor.s4',
        noteKey: 'topology.workflows.vendor.s4n',
        evidence: { file: VENDOR_FIXTURES, contains: 'TICKET_UNCONFIGURED_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/vendors/{vendor_id}/approve',
        labelKey: 'topology.workflows.vendor.s5',
        noteKey: 'topology.workflows.vendor.s5n',
        evidence: { file: VENDOR_FIXTURES, contains: 'APPROVE_MISSING_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/vendors/{vendor_id}/requests',
        labelKey: 'topology.workflows.vendor.s6',
        evidence: { file: VENDOR_FIXTURES, contains: 'REQUEST_FILED_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/vendors/{vendor_id}/revoke',
        labelKey: 'topology.workflows.vendor.s7',
        evidence: { file: VENDOR_FIXTURES, contains: 'REVOKE_RESPONSE' },
      },
    ],
  },
  {
    id: 'jit',
    titleKey: 'topology.workflows.jit.title',
    subtitleKey: 'topology.workflows.jit.subtitle',
    steps: [
      {
        operation: 'POST /api/v1/jit/requests',
        labelKey: 'topology.workflows.jit.s1',
        evidence: { file: JIT_FIXTURES, contains: 'JIT_FILED_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/jit/requests/{request_id}/approve',
        labelKey: 'topology.workflows.jit.s2',
        evidence: { file: JIT_FIXTURES, contains: 'JIT_APPROVE_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/jit/requests/{request_id}/deny',
        labelKey: 'topology.workflows.jit.s3',
        noteKey: 'topology.workflows.jit.s3n',
        evidence: { file: JIT_FIXTURES, contains: 'JIT_DENY_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/jit/requests/{request_id}/consume',
        labelKey: 'topology.workflows.jit.s4',
        noteKey: 'topology.workflows.jit.s4n',
        evidence: { file: JIT_FIXTURES, contains: 'JIT_GRANT_RESPONSE' },
      },
      {
        operation: 'POST /api/v1/jit/requests/{request_id}/close',
        labelKey: 'topology.workflows.jit.s5',
        evidence: { file: JIT_FIXTURES, contains: 'JIT_CLOSE_RESPONSE' },
      },
    ],
  },
];
