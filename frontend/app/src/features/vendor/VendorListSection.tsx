import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader } from '../../components';
import type { VendorAccount } from '../../api/generated/models';
import { ACTION_OPS, canOperate } from '../../app/guards/RoleGate';
import { useAuth } from '../../app/providers/useAuth';
import { SectionBody } from './SectionBody';
import { useInviteVendor, useVendors } from './queries';
import { vendorStatuses } from './schemas';
import type { VendorSeed } from './SeedCard';

/** The status chips the contract's filter enum offers, `all` first. */
const STATUS_FILTERS: readonly ('all' | (typeof vendorStatuses)[number])[] = [
  'all',
  ...vendorStatuses,
];

/** Active statuses read `info`, terminal ones read `inactive` (tones). */
function statusTone(status: VendorAccount['status']): 'info' | 'inactive' {
  return status === 'invited' || status === 'approved' ? 'info' : 'inactive';
}

/**
 * The vendor registry (F4 screen 8, plan line 114 "Chain steps, invite,
 * scoped requests"). The status chips and the search drive real
 * contract parameters (`status` by equality, `q` as a substring over
 * name/contact) - the list refetches from the server, it is never
 * re-filtered client-side from a stale page. Every row shows its four
 * chain steps raw from the account; "Reinvite" re-POSTs the same name
 * exactly like the legacy button (the server answers a fresh cycle on
 * denied/revoked/expired rows and refuses a live one verbatim), and the
 * returned one-time seed goes to the page's seed card.
 */
export function VendorListSection({
  actor,
  selectedId,
  onSelect,
  onSeed,
}: {
  actor: string;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  onSeed: (seed: VendorSeed | null) => void;
}) {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  // D3: inviting (and reinviting) an account is administrator-class - the
  // operator may file access requests for an invited vendor, not create one.
  const canInvite = canOperate(ACTION_OPS.vendorCreate, whoami);

  const [status, setStatus] = useState<(typeof vendorStatuses)[number] | undefined>(
    undefined,
  );
  const [q, setQ] = useState('');

  const vendors = useVendors({ status, q });
  const inviteVendor = useInviteVendor();

  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  /** Reinvite: the invite call again with the row's own name (legacy parity). */
  const reinvite = (vendor: VendorAccount) => {
    setActionStatus(null);
    setActionError(null);
    inviteVendor.mutate(
      { actor, payload: { name: vendor.name } },
      {
        onSuccess: (data) => {
          setActionStatus(data.message);
          onSeed({ name: data.vendor.name, mfa: data.mfa });
        },
        onError: (err) => setActionError(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('vendor.list.title')}
        subtitle={t('vendor.list.subtitle')}
        actions={
          vendors.data
            ? t('vendor.list.count', {
                shown: vendors.data.vendors.length,
                total: vendors.data.total,
              })
            : undefined
        }
      />
      <div className="flex flex-wrap items-center gap-space-sm">
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('vendor.list.filterStatus')}
        >
          {STATUS_FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={(status ?? 'all') === value}
              onClick={() => setStatus(value === 'all' ? undefined : value)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                (status ?? 'all') === value
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {value === 'all' ? t('vendor.list.filterAll') : value}
            </button>
          ))}
        </div>
        <input
          value={q}
          onChange={(event) => setQ(event.target.value)}
          placeholder={t('vendor.list.searchPlaceholder')}
          aria-label={t('vendor.list.searchPlaceholder')}
          className="w-56 rounded bg-surface-container-low p-2 font-body-sm text-body-sm text-on-surface focus:outline-none"
        />
      </div>
      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-code-sm text-code-sm text-tertiary"
      >
        {actionStatus ?? ''}
      </p>
      <p
        role="alert"
        className={`min-h-5 font-code-sm text-code-sm text-error${actionError ? '' : ' hidden'}`}
      >
        {actionError ?? ''}
      </p>
      <SectionBody query={vendors}>
        {(data) =>
          data.vendors.length === 0 ? (
            <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
              {t('vendor.list.empty')}
            </p>
          ) : (
            <div className="flex flex-col gap-space-sm">
              {data.vendors.map((vendor) => (
                <div
                  key={vendor.id}
                  className={`flex flex-col gap-space-xs rounded-lg border px-space-md py-space-sm ${
                    selectedId === vendor.id
                      ? 'border-primary/40 bg-surface-container-low'
                      : 'border-outline-variant/30 bg-surface-container-lowest'
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-space-sm">
                    <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                      {vendor.name}
                    </span>
                    <Chip tone={statusTone(vendor.status)}>{vendor.status}</Chip>
                    {vendor.contact ? (
                      <span className="font-body-sm text-body-sm text-on-surface-variant">
                        {vendor.contact}
                      </span>
                    ) : null}
                    <span className="ml-auto flex flex-wrap gap-space-sm">
                      <Button
                        type="button"
                        variant="secondary"
                        onClick={() => onSelect(vendor.id)}
                      >
                        {t('vendor.list.open')}
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        disabled={inviteVendor.isPending || !canInvite}
                        title={canInvite ? undefined : t('roleReasons.administrator')}
                        onClick={() => reinvite(vendor)}
                      >
                        {t('vendor.list.reinvite')}
                      </Button>
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-1">
                    <Chip tone={vendor.steps.mfa === 'verified' ? 'info' : 'inactive'}>
                      {`mfa: ${vendor.steps.mfa}`}
                    </Chip>
                    <Chip tone={vendor.steps.nda === 'signed' ? 'info' : 'inactive'}>
                      {`nda: ${vendor.steps.nda}`}
                    </Chip>
                    <Chip tone={vendor.steps.ticket === 'verified' ? 'info' : 'inactive'}>
                      {`ticket: ${vendor.steps.ticket}`}
                    </Chip>
                    <Chip tone={vendor.steps.approval === 'approved' ? 'info' : 'inactive'}>
                      {`approval: ${vendor.steps.approval}`}
                    </Chip>
                  </div>
                  <div className="flex flex-wrap gap-space-sm font-code-sm text-code-sm text-outline">
                    <span>
                      {vendor.access.window !== null
                        ? t('vendor.list.window', { window: vendor.access.window })
                        : t('vendor.list.anyHour')}
                    </span>
                    <span>
                      {t('vendor.list.allowed', { count: vendor.access.allowed.length })}
                    </span>
                    <span>
                      {vendor.access.expires_at !== null
                        ? t('vendor.list.expiresAt', { at: vendor.access.expires_at })
                        : t('vendor.list.noExpiry')}
                    </span>
                  </div>
                  {vendor.denied_reason ? (
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {t('vendor.list.reason', { reason: vendor.denied_reason })}
                    </span>
                  ) : null}
                </div>
              ))}
            </div>
          )
        }
      </SectionBody>
    </div>
  );
}
