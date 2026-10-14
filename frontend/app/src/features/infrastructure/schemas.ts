import { z } from 'zod';

/**
 * Target Infrastructure form schemas (ADR-0006: RHF + Zod, client UX
 * only - the server-side contract validation is always authoritative).
 * Field limits mirror `apis/openapi.yaml` exactly, never tighter: a
 * client rule that disagreed with the contract would hide real server
 * behaviour.
 */

/** `DiscoveryAssetType` enum, mirrored from the contract. */
export const assetTypes = [
  'windows',
  'linux',
  'unix',
  'aix',
  'solaris',
  'vmware',
  'hyperv',
  'kubernetes',
  'docker',
  'network',
  'firewall',
  'loadbalancer',
  'database',
  'cloud',
  'unknown',
] as const;

/** `DiscoveryPamStatus` enum, mirrored from the contract. */
export const pamStatuses = ['unmanaged', 'managed', 'ignored'] as const;

/** `CloudConnector.provider` enum, mirrored from the contract. */
export const connectorProviders = ['aws', 'azure', 'gcp', 'kubernetes'] as const;

/** `CloudConnector.status` enum, mirrored from the contract. */
export const connectorStatuses = [
  'not connected',
  'configured',
  'connected',
  'error',
] as const;

/** The access tiers both onboarding payloads accept, from the contract. */
export const accessTiers = ['Tier-0', 'Tier-1', 'Tier-2'] as const;

/** IPv4 dotted quad (octet validation stays server-side). */
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
/** IPv4 CIDR (the scan contract caps the block at 256 hosts server-side). */
const CIDR = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;
/** Hostname: label-ish, no spaces or slashes. */
const HOSTNAME = /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,62}[a-zA-Z0-9])?$/;

/**
 * `DiscoveryScanRequest`: scope required (IPv4 / IPv4 CIDR / hostname,
 * <= 64 chars - the contract's own rule), ports optional. The contract
 * defaults the port set when `ports` is absent, so the CSV the operator
 * types is parsed to `number[] | undefined` and the empty form simply
 * keeps the parameter absent rather than sending a fabricated set.
 */
export const scanSchema = z.object({
  scope: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .refine(
      (v) => IPV4.test(v) || CIDR.test(v) || HOSTNAME.test(v),
      'IPv4 address, IPv4 CIDR or hostname',
    ),
  portsText: z
    .string()
    .trim()
    .max(64)
    .refine(
      (v) =>
        v === '' ||
        (v.split(',').length <= 24 &&
          v
            .split(',')
            .every(
              (p) => /^\d{1,5}$/.test(p.trim()) && Number(p) >= 1 && Number(p) <= 65535,
            )),
      'comma-separated ports 1-65535 (max 24)',
    )
    .transform((v) => (v === '' ? undefined : v.split(',').map((p) => Number(p.trim())))),
});
export type ScanValues = z.output<typeof scanSchema>;
/** Form-state twin (kept for the shared page pattern). */
export type ScanForm = z.input<typeof scanSchema>;

/**
 * `DiscoveryOnboardRequest`: address and principal required; every
 * other field optional with the contract's max length. The contract
 * refuses a CIDR here ("single IPv4 address or hostname") - mirrored in
 * the UX, with the 400 still authoritative. Rotation hours stay a text
 * field parsed to `number | undefined` so an empty input keeps the
 * contract's default instead of posting zero.
 */
export const onboardSchema = z.object({
  address: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .refine((v) => !v.includes('/'), 'single address or hostname, not a CIDR'),
  hostname: z.string().trim().max(255),
  asset_type: z.enum(assetTypes),
  notes: z.string().trim().max(255),
  principal: z.string().trim().min(1).max(128),
  access_tier: z.enum(accessTiers),
  auth_method: z.string().trim().max(32),
  rotationText: z
    .string()
    .trim()
    .max(5)
    .refine((v) => v === '' || (/^\d{1,4}$/.test(v) && Number(v) <= 8760), '0-8760 hours')
    .transform((v) => (v === '' ? undefined : Number(v))),
});
export type OnboardValues = z.output<typeof onboardSchema>;
export type OnboardForm = z.input<typeof onboardSchema>;

/**
 * `DiscoveryAdoptRequest` - "Onboard to Vault Now" on a discovered
 * target: principal required, tier / auth / rotation mirror the same
 * contract defaults the onboard call carries.
 */
export const adoptSchema = z.object({
  principal: z.string().trim().min(1).max(128),
  access_tier: z.enum(accessTiers),
  auth_method: z.string().trim().max(32),
  rotationText: z
    .string()
    .trim()
    .max(5)
    .refine((v) => v === '' || (/^\d{1,4}$/.test(v) && Number(v) <= 8760), '0-8760 hours')
    .transform((v) => (v === '' ? undefined : Number(v))),
});
export type AdoptValues = z.output<typeof adoptSchema>;
export type AdoptForm = z.input<typeof adoptSchema>;

/**
 * `CloudConnectorCreate`: name and provider required; account_ref and
 * endpoint optional. The contract endpoint rule is "https (http only on
 * loopback)" - mirrored as a UX guard; the 400 stays authoritative.
 * Regions / services / credential_item_id are optional contract fields
 * the legacy modal never exposed, so this form omits them too.
 */
export const connectorSchema = z.object({
  name: z.string().trim().min(2).max(64),
  provider: z.enum(connectorProviders),
  account_ref: z.string().trim().max(128),
  endpoint: z
    .string()
    .trim()
    .max(255)
    .refine(
      (v) =>
        v === '' ||
        v.startsWith('https://') ||
        /^http:\/\/(127\.|localhost|\[::1\])/.test(v),
      'https:// URL (http only for loopback)',
    ),
});
export type ConnectorValues = z.infer<typeof connectorSchema>;
export type ConnectorForm = z.input<typeof connectorSchema>;
