import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  deleteApiV1RoleBindingsBindingId,
  getApiV1AuthEmergency,
  getApiV1AuthSsoStatus,
  getApiV1Cluster,
  getApiV1ClusterBackups,
  getApiV1HsmStatus,
  getApiV1IntegrationsStatus,
  getApiV1RoleBindings,
  getApiV1Roles,
  getApiV1Settings,
  getApiV1SettingsAudit,
  postApiV1AuthEmergencyOpen,
  postApiV1AuthLdap,
  postApiV1ItsmVerify,
  postApiV1MfaEnroll,
  postApiV1RoleBindings,
  postApiV1SettingsScimRotate,
  postApiV1SettingsSmtpTest,
  putApiV1SettingsGroup,
} from '../../api/generated';
import type {
  ClusterBackupList,
  ClusterOverview,
  DeleteApiV1RoleBindingsBindingId200,
  GetApiV1AuthEmergency200,
  HsmStatus,
  IntegrationsStatus,
  ItsmVerifyRequest,
  ItsmVerifyResponse,
  LdapLoginRequest,
  LdapLoginResponse,
  MfaEnrollResponse,
  PostApiV1AuthEmergencyOpen201,
  PostApiV1AuthEmergencyOpenBody,
  PostApiV1RoleBindings201,
  PostApiV1SettingsScimRotate200,
  PostApiV1SettingsSmtpTest200,
  PutApiV1SettingsGroupBody,
  RoleBindingCreate,
  RoleBindingList,
  RoleList,
  SettingsAuditResponse,
  SettingsResponse,
  SettingsWriteResponse,
  SsoStatus,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';
import type { SettingsGroupName } from './settingsSchema';

/**
 * Platform Settings (screen 11, ADR-0015) read hooks for the 11.1 slice:
 * the read-only posture sections, plus the 11.2 RBAC directory reads and
 * the two binding writes. Every read goes through the generated client
 * and `expectOk`, so a non-2xx surfaces the server's own error verbatim
 * and a dead backend becomes the shared BackendDown error the page
 * renders as its honest down-state - never a zeroed posture that would
 * read as "healthy".
 *
 * The reads mirror the endpoints the legacy `platform_settings_center`
 * page already calls (inventory in ADR-0015). 11.1 ships four sections:
 * SSO federation, HSM custody, the Enterprise Integrations chips and the
 * HA/DC/DR cluster posture (overview + its backup ledger). 11.2 adds the
 * role directory and binding table with the grant/revoke writes. The 11.3
 * slice adds the settings schema+values read, the config changelog and
 * the three writes (group PUT, SMTP test message, SCIM token rotation)
 * on this same `['settings', ...]` root. The 11.4 slice adds the sealed
 * emergency admin (state read + the dual-approved open request) and the
 * integrations actions - MFA enrol (legacy parity) plus ITSM verify and
 * LDAP bind (NEW actions, ADR-0015 amendment 11.4).
 */

/** `GET /api/v1/auth/sso/status` - IdP federation posture. */
export function useSsoStatus(): UseQueryResult<SsoStatus> {
  return useQuery({
    queryKey: queryKeys.settingsSso,
    queryFn: async () => expectOk(await getApiV1AuthSsoStatus()).data,
  });
}

/** `GET /api/v1/hsm/status` - key custody posture (sealed / mode / key). */
export function useHsmStatus(): UseQueryResult<HsmStatus> {
  return useQuery({
    queryKey: queryKeys.settingsHsm,
    queryFn: async () => expectOk(await getApiV1HsmStatus()).data,
  });
}

/** `GET /api/v1/integrations/status` - the enterprise connector chips. */
export function useIntegrationsStatus(): UseQueryResult<IntegrationsStatus> {
  return useQuery({
    queryKey: queryKeys.settingsIntegrations,
    queryFn: async () => expectOk(await getApiV1IntegrationsStatus()).data,
  });
}

/**
 * `GET /api/v1/cluster` - the HA/DC/DR aggregate (self, peers,
 * replication, backups, monitor). Verbatim rig capture: a pristine node
 * reports `{}` for `peers`/`backups` rather than an empty object with
 * zeroed counters, so every consumer treats those blocks as optional and
 * renders honest zeros - never invented peers.
 */
export function useClusterOverview(): UseQueryResult<ClusterOverview> {
  return useQuery({
    queryKey: queryKeys.settingsCluster,
    queryFn: async () => expectOk(await getApiV1Cluster()).data,
  });
}

/** `GET /api/v1/cluster/backups` - the backup ledger rows. */
export function useClusterBackups(): UseQueryResult<ClusterBackupList> {
  return useQuery({
    queryKey: queryKeys.settingsClusterBackups,
    queryFn: async () => expectOk(await getApiV1ClusterBackups()).data,
  });
}

/**
 * `GET /api/v1/roles` - the seeded role directory. Verbatim rig capture:
 * exactly five built-in roles, each carrying its computed `operations`
 * count, so the page never hardcodes the count (it reads what the server
 * actually seeded).
 */
export function useRoles(): UseQueryResult<RoleList> {
  return useQuery({
    queryKey: queryKeys.settingsRoles,
    queryFn: async () => expectOk(await getApiV1Roles()).data,
  });
}

/**
 * `GET /api/v1/role-bindings` - who holds what (principal, role, kind,
 * ABAC scope, last use). The list can legitimately be empty on a fresh
 * node; the page renders the honest empty row, never a fabricated grant.
 */
export function useRoleBindings(): UseQueryResult<RoleBindingList> {
  return useQuery({
    queryKey: queryKeys.settingsBindings,
    queryFn: async () => expectOk(await getApiV1RoleBindings()).data,
  });
}

/**
 * `POST /api/v1/role-bindings` - grant a role. A `local` principal gets
 * its API token minted ONCE in the 201 body (never recoverable, sha256
 * at rest); an `ldap`/`sso`/`user` principal is a directory identity
 * that gets no token back. Both writes invalidate the role + binding
 * reads so the tiles, summary line and tables re-read the same registry.
 */
export function useCreateRoleBinding(): UseMutationResult<
  PostApiV1RoleBindings201,
  unknown,
  RoleBindingCreate
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (payload: RoleBindingCreate) =>
      expectOk(await postApiV1RoleBindings(payload)).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsRoles });
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsBindings });
    },
  });
}

/**
 * `DELETE /api/v1/role-bindings/{id}` - revoke a grant. The token stops
 * working immediately and the row stays as audit evidence (the server
 * stamps `revoked_at`), so the bindings read is invalidated to show it.
 */
export function useRevokeRoleBinding(): UseMutationResult<
  DeleteApiV1RoleBindingsBindingId200,
  unknown,
  number
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (bindingId: number) =>
      expectOk(await deleteApiV1RoleBindingsBindingId(bindingId)).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsBindings });
    },
  });
}

/**
 * `GET /api/v1/settings` - the render schema plus the stored-or-default
 * values for all 15 groups (11.3). The schema's per-field descriptors
 * (type, min/max, max_length, allow_empty, choices, readonly) are what
 * the Zod rules and the control mapping derive from - the page never
 * hardcodes a field list.
 */
export function useSettingsGroups(): UseQueryResult<SettingsResponse> {
  return useQuery({
    queryKey: queryKeys.settingsGroups,
    queryFn: async () => expectOk(await getApiV1Settings()).data,
  });
}

/**
 * `GET /api/v1/settings/audit?limit=20` - the configuration changelog
 * (11.3): which group's fields changed, by whom, when. The legacy page
 * asks for exactly 20 rows; the key is fixed to that limit.
 */
export function useSettingsAudit(): UseQueryResult<SettingsAuditResponse> {
  return useQuery({
    queryKey: queryKeys.settingsAudit,
    queryFn: async () => expectOk(await getApiV1SettingsAudit({ limit: 20 })).data,
  });
}

/**
 * `PUT /api/v1/settings/{group}` - merge one group's fields (11.3).
 * No `onSuccess` invalidation here on purpose: the save controller loops
 * several dirty groups and must keep the form's dirty state intact until
 * the WHOLE loop succeeds (or stops honestly at the first refusal), then
 * invalidates the settings root once - the same load-after-save the
 * legacy page does.
 */
export function usePutSettingsGroup(): UseMutationResult<
  SettingsWriteResponse,
  unknown,
  { group: SettingsGroupName; body: PutApiV1SettingsGroupBody }
> {
  return useMutation({
    mutationFn: async ({
      group,
      body,
    }: {
      group: SettingsGroupName;
      body: PutApiV1SettingsGroupBody;
    }) => expectOk(await putApiV1SettingsGroup(group, body)).data,
  });
}

/**
 * `POST /api/v1/settings/smtp/test` - send a real test message through
 * the configured SMTP server (11.3). The pristine rig answers the honest
 * 503 refusal naming what to set; that refusal IS the rendered feedback,
 * never a swallowed failure.
 */
export function useSmtpTest(): UseMutationResult<
  PostApiV1SettingsSmtpTest200,
  unknown,
  string
> {
  return useMutation({
    mutationFn: async (to: string) =>
      expectOk(await postApiV1SettingsSmtpTest({ to })).data,
  });
}

/**
 * `POST /api/v1/settings/scim/rotate` - mint a fresh SCIM bearer token
 * (11.3). The token is shown exactly once (the response is the only
 * place it ever exists); the rotate stamps the `scim` group itself
 * (`stored`, `enabled`, `token_sha256`), so the settings root is
 * invalidated for the re-read.
 */
export function useScimRotate(): UseMutationResult<
  PostApiV1SettingsScimRotate200,
  unknown,
  void
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => expectOk(await postApiV1SettingsScimRotate()).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsRoot });
    },
  });
}

/**
 * `GET /api/v1/auth/emergency` - the sealed emergency admin's grants and
 * username (11.4, legacy parity code.html:1311). The pristine rig answers
 * `grants: []`; a denied grant stays in the history forever (audit), so
 * consumers derive the state line exactly like the legacy does: open >
 * pending > sealed.
 */
export function useEmergencyStatus(): UseQueryResult<GetApiV1AuthEmergency200> {
  return useQuery({
    queryKey: queryKeys.settingsEmergency,
    queryFn: async () => expectOk(await getApiV1AuthEmergency()).data,
  });
}

/**
 * `POST /api/v1/auth/emergency/open` - request a pending grant awaiting
 * two distinct approvals (11.4). Reason is 8..255 chars server-side; a
 * short reason answers the verbatim 400 the card renders. Success
 * re-reads the emergency view (the new pending state disables the button,
 * same as the legacy `loadEmergency()` after the POST).
 */
export function useEmergencyOpen(): UseMutationResult<
  PostApiV1AuthEmergencyOpen201,
  unknown,
  PostApiV1AuthEmergencyOpenBody
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: PostApiV1AuthEmergencyOpenBody) =>
      expectOk(await postApiV1AuthEmergencyOpen(body)).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsEmergency });
    },
  });
}

/**
 * `POST /api/v1/mfa/enroll` - mint this operator's TOTP factor; the seed
 * and `otpauth://` URI exist in exactly this response (11.4, legacy
 * parity code.html:1702). Success invalidates the settings root the way
 * the legacy `loadAll()` re-reads everything: the readonly `mfa.factor_*`
 * fields move with the chip.
 */
export function useMfaEnroll(): UseMutationResult<MfaEnrollResponse, unknown, void> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => expectOk(await postApiV1MfaEnroll({})).data,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.settingsRoot });
    },
  });
}

/**
 * `POST /api/v1/itsm/verify` - a real REST lookup against the configured
 * instance (11.4 NEW action; the legacy page has no button for it - ADR
 * amendment 11.4). The pristine rig refuses with the verbatim 409 before
 * any HTTP call; that refusal IS the rendered feedback.
 */
export function useItsmVerify(): UseMutationResult<
  ItsmVerifyResponse,
  unknown,
  ItsmVerifyRequest
> {
  return useMutation({
    mutationFn: async (request: ItsmVerifyRequest) =>
      expectOk(await postApiV1ItsmVerify(request)).data,
  });
}

/**
 * `POST /api/v1/auth/ldap` - a real BER BindRequest against the configured
 * directory (11.4 NEW action; no legacy button - ADR amendment 11.4). The
 * configured check runs BEFORE any bind, so the pristine rig answers the
 * verbatim 409 and the password never leaves the request. A 200 can carry
 * a one-time admin ticket (token mode) - never re-readable.
 */
export function useLdapBind(): UseMutationResult<
  LdapLoginResponse,
  unknown,
  LdapLoginRequest
> {
  return useMutation({
    mutationFn: async (request: LdapLoginRequest) =>
      expectOk(await postApiV1AuthLdap(request)).data,
  });
}
