import { useMutation, useQuery } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import {
  getApiV1AuditExport,
  getApiV1AuditStats,
  getApiV1AuditVerify,
  getApiV1Events,
  getApiV1IntegrationsStatus,
} from '../../api/generated';
import type {
  AuditStats,
  AuditVerify,
  EventFeed,
  EventFeedSource,
  IntegrationsStatus,
} from '../../api/generated/models';
import { expectOk } from '../../api/http';
import type { HttpEnvelope } from '../../api/http';
import { queryKeys } from '../../api/queryKeys';

/**
 * Compliance & SOC2 data hooks (F4 screen 6, plan §4 line 111: "Ledger
 * digest, verify walk, export, source chips"). Every read goes through
 * the generated client and `expectOk`. This screen has no writes at all
 * (the ledger is append-only server side), so nothing here carries
 * `X-Actor`. One `['compliance', ...]` key root keeps the digest, the
 * trail and the connector chips refreshing together - they are views of
 * the same store.
 *
 * The verify walk and the export are on-demand mutations, not cached
 * reads: the walk re-hashes the whole chain server side and the export
 * pulls the full ledger, so both run on click like the legacy console.
 */

/** Trail page the legacy compliance screen rendered (contract max 200). */
export const COMPLIANCE_EVENTS_LIMIT = 50;

/* ------------------------------------------------------------------ reads */

/** `GET /api/v1/audit/stats` - the real ledger digest aggregates. */
export function useAuditStats(): UseQueryResult<AuditStats> {
  return useQuery<AuditStats>({
    queryKey: queryKeys.complianceStats,
    queryFn: async () => (await expectOk(await getApiV1AuditStats())).data,
  });
}

/** `GET /api/v1/events?source=&limit=` - the unified trail, filtered. */
export function useAuditEvents(source: EventFeedSource): UseQueryResult<EventFeed> {
  return useQuery<EventFeed>({
    queryKey: queryKeys.complianceEvents(source, COMPLIANCE_EVENTS_LIMIT),
    queryFn: async () => {
      // The contract's `all` state is the ABSENT parameter (the enum the
      // client may send holds eleven sources; the envelope reports 'all').
      const params =
        source === 'all'
          ? { limit: COMPLIANCE_EVENTS_LIMIT }
          : { source, limit: COMPLIANCE_EVENTS_LIMIT };
      return (await expectOk(await getApiV1Events(params))).data;
    },
  });
}

/** `GET /api/v1/integrations/status` - the honest connector/SIEM chips. */
export function useIntegrationsStatus(): UseQueryResult<IntegrationsStatus> {
  return useQuery<IntegrationsStatus>({
    queryKey: queryKeys.complianceIntegrations,
    queryFn: async () => (await expectOk(await getApiV1IntegrationsStatus())).data,
  });
}

/* ------------------------------------------------------ on-demand actions */

/**
 * `GET /api/v1/audit/verify` - walk the hash chain on click (the server
 * re-hashes every record and re-links the prev-hashes; this is a chain
 * walk, not a Merkle proof - the legacy screen corrected its own label
 * at runtime, this screen just says what runs).
 */
export function useVerifyChain(): UseMutationResult<AuditVerify, Error, void> {
  return useMutation<AuditVerify, Error, void>({
    mutationFn: async () => (await expectOk(await getApiV1AuditVerify())).data,
  });
}

/**
 * `GET /api/v1/audit/export` - the whole ledger as NDJSON text.
 *
 * orval types this `application/x-ndjson` arm as `{stream}` while the
 * shared mutator resolves the standard `{status, data}` envelope with
 * the raw text in `data` (http.ts keeps non-JSON bodies verbatim), so
 * the envelope is bridged through a documented cast - the runtime shape
 * is the contract's own: a newline-delimited JSON string.
 */
export function useExportLedger(): UseMutationResult<string, Error, void> {
  return useMutation<string, Error, void>({
    mutationFn: async () => {
      const envelope = (await getApiV1AuditExport()) as unknown as HttpEnvelope<string> & {
        status: 200;
      };
      return expectOk(envelope).data;
    },
  });
}
