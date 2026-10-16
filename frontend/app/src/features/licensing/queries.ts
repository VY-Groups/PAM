import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1Licenses,
  getApiV1LicensesLicenseKey,
  getApiV1LicensesLicenseKeyFile,
  getApiV1Meta,
  getApiV1Overview,
  postApiV1LicensesImport,
  postApiV1LicensesLicenseKeyRestore,
  postApiV1LicensesLicenseKeyRevoke,
  postApiV1LicensesValidate,
} from '../../api/generated';
import type {
  GetApiV1LicensesLicenseKey200,
  GetApiV1LicensesParams,
  GetApiV1LicensesStatus,
  ImportLicenseResponse,
  LicenseEnvelope,
  LicenseList,
  LicenseMutationResponse,
  Meta,
  Overview,
  PostApiV1LicensesValidateBodyOne,
  ValidationResult,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Enterprise Licensing data hooks (F4 screen 10, the successor of
 * `enterprise_licensing_tier_entitlements_node_quotas`: tiers,
 * entitlements and node quotas). Every read goes through the generated
 * client and `expectOk`; the list sends its filters server-side exactly
 * as the contract offers them (`status`/`tier`/`license_type` by
 * equality, `q` as the free-text search across key, ID and subject), so
 * the chips and selects drive real contract parameters - never a client
 * re-filter of a stale page.
 *
 * The screen is read-plus-lifecycle: import (the offline air-gap
 * ingestion), validate (the offline-parity verdict), revoke with a
 * reason and restore - each answers the server's own message verbatim.
 * One `['licensing', ...]` key root keeps every view refreshing
 * together: an import moves the registry, the overview aggregates and
 * the detail at once.
 */

/** Contract limit for the registry list (max 200). */
export const LICENSES_LIST_LIMIT = 200;

/** The list filter state; empty string means "no filter" (contract default). */
export interface LicenseFilters {
  status: '' | GetApiV1LicensesStatus;
  tier: string;
  licenseType: string;
  q: string;
}

/** `GET /api/v1/overview` - the aggregates behind the KPI quad. */
export function useLicensingOverview(): UseQueryResult<Overview> {
  return useQuery({
    queryKey: queryKeys.licensingOverview,
    queryFn: async () => expectOk(await getApiV1Overview()).data,
  });
}

/** `GET /api/v1/meta` - the platform catalog (tiers, types, algorithms). */
export function useLicenseMeta(): UseQueryResult<Meta> {
  return useQuery({
    queryKey: queryKeys.licensingMeta,
    queryFn: async () => expectOk(await getApiV1Meta()).data,
  });
}

/** `GET /api/v1/licenses` - the registry with server-side filters. */
export function useLicenseList(filters: LicenseFilters): UseQueryResult<LicenseList> {
  const params: GetApiV1LicensesParams = { limit: LICENSES_LIST_LIMIT };
  if (filters.status !== '') params.status = filters.status;
  if (filters.tier !== '') params.tier = filters.tier;
  if (filters.licenseType !== '') params.license_type = filters.licenseType;
  if (filters.q.trim() !== '') params.q = filters.q.trim();
  return useQuery({
    queryKey: queryKeys.licensingList(
      filters.status,
      filters.tier,
      filters.licenseType,
      filters.q.trim(),
    ),
    queryFn: async () => expectOk(await getApiV1Licenses(params)).data,
  });
}

/** `GET /api/v1/licenses/{license_key}` - one license's full record + events. */
export function useLicenseDetail(
  licenseKey: string | null,
): UseQueryResult<GetApiV1LicensesLicenseKey200> {
  return useQuery({
    queryKey: queryKeys.licensingDetail(licenseKey),
    queryFn: async () => expectOk(await getApiV1LicensesLicenseKey(licenseKey ?? '')).data,
    enabled: licenseKey !== null,
  });
}

/**
 * `GET /api/v1/licenses/{license_key}/file` - the signed file. The
 * contract serves the json envelope as JSON and the jwt as raw
 * `text/plain`; the shared mutator passes non-JSON bodies through
 * verbatim, so both arms arrive intact.
 */
export function useLicenseFile(
  licenseKey: string | null,
  format: 'json' | 'jwt',
  enabled: boolean,
): UseQueryResult<unknown> {
  return useQuery({
    queryKey: queryKeys.licensingFile(licenseKey, format),
    queryFn: async () =>
      expectOk(await getApiV1LicensesLicenseKeyFile(licenseKey ?? '', { format })).data,
    enabled: enabled && licenseKey !== null,
  });
}

/** Every lifecycle write invalidates the whole screen root at once. */
function invalidateScreen(queryClient: ReturnType<typeof useQueryClient>): void {
  void queryClient.invalidateQueries({ queryKey: ['licensing'] });
}

/**
 * `POST /api/v1/licenses/import` - the offline air-gap ingestion. The
 * server verifies the signature against its own key before storing, so
 * a tampered envelope is refused with its reason (rendered verbatim).
 */
export function useImportLicense(): UseMutationResult<
  ImportLicenseResponse,
  unknown,
  LicenseEnvelope
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (envelope: LicenseEnvelope) =>
      expectOk(await postApiV1LicensesImport(envelope)).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/licenses/{key}/revoke` - terminal revocation with a
 * recorded reason; the server answers the mutation message verbatim.
 */
export function useRevokeLicense(): UseMutationResult<
  LicenseMutationResponse,
  unknown,
  { licenseKey: string; reason: string }
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ licenseKey, reason }: { licenseKey: string; reason: string }) =>
      expectOk(
        await postApiV1LicensesLicenseKeyRevoke(licenseKey, {
          reason: reason !== '' ? reason : undefined,
        }),
      ).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/** `POST /api/v1/licenses/{key}/restore` - un-revoke a revoked license. */
export function useRestoreLicense(): UseMutationResult<
  LicenseMutationResponse,
  unknown,
  string
> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (licenseKey: string) =>
      expectOk(await postApiV1LicensesLicenseKeyRestore(licenseKey)).data,
    onSuccess: () => invalidateScreen(queryClient),
  });
}

/**
 * `POST /api/v1/licenses/validate` - the offline-parity verdict. The
 * contract accepts the envelope, a wrapper or the compact jwt token as
 * a string; the server answers validity, signature, registration and
 * revocation state without touching the registry.
 */
export function useValidateLicense(): UseMutationResult<
  ValidationResult,
  unknown,
  PostApiV1LicensesValidateBodyOne
> {
  return useMutation({
    mutationFn: async (body: PostApiV1LicensesValidateBodyOne) =>
      expectOk(await postApiV1LicensesValidate(body)).data,
  });
}
