import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, DataTable, SectionHeader } from '../../components';
import type { LicenseList, LicenseRecord, Meta } from '../../api/generated/models';
import type { GetApiV1LicensesStatus } from '../../api/generated/models';
import { SectionBody } from './SectionBody';
import { useLicenseList } from './queries';
import { licenseStatuses } from './schemas';

/** The status chips the contract's filter enum offers, `all` first. */
const STATUS_FILTERS: readonly ('all' | (typeof licenseStatuses)[number])[] = [
  'all',
  ...licenseStatuses,
];

/** The server's own lifecycle reads marked; terminal/void states stay quiet. */
function statusTone(status: LicenseRecord['effective_status']): 'info' | 'inactive' {
  // The rig answers 'valid' for a live license (captured), so anything
  // that is not revoked or expired is the marked state.
  return status === 'revoked' || status === 'expired' ? 'inactive' : 'info';
}

/**
 * The license registry (F4 screen 10). Every control drives a real
 * contract parameter - the status chips (`status` by equality), the
 * tier and type selects (`tier`/`license_type` by equality) and the
 * free-text search (`q`, matched server-side against key, ID and
 * subject) - so the list refetches from the server; it is never
 * re-filtered client-side from a stale page. Row selection hands the
 * license key up to the page for the detail section, mirroring the
 * legacy screen's "click a license to inspect it" flow.
 */
export function LicenseListSection({
  meta,
  selectedKey,
  onSelect,
}: {
  /** The `/api/v1/meta` catalog (tier/type options come from the contract). */
  meta: Meta | undefined;
  /** Currently inspected license key, for the row highlight. */
  selectedKey: string | null;
  onSelect: (licenseKey: string) => void;
}) {
  const { t } = useTranslation();

  const [status, setStatus] = useState<'' | GetApiV1LicensesStatus>('');
  const [tier, setTier] = useState('');
  const [licenseType, setLicenseType] = useState('');
  const [q, setQ] = useState('');

  const licenses = useLicenseList({ status, tier, licenseType, q });

  const columns = [
    {
      key: 'identity',
      header: t('licensing.list.colIdentity'),
      render: (row: LicenseRecord) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-sm text-code-sm font-semibold text-on-surface">
            {row.license_id ?? row.license_key}
          </span>
          <span className="font-code-sm text-code-sm text-outline">{row.license_key}</span>
        </div>
      ),
    },
    {
      key: 'subject',
      header: t('licensing.list.colSubject'),
      render: (row: LicenseRecord) => (
        <div className="font-code-sm text-code-sm">
          {row.issued_to ?? '—'}
          <div className="text-outline">
            {row.subject_entity ?? row.classification ?? '—'}
          </div>
        </div>
      ),
    },
    {
      key: 'tier',
      header: t('licensing.list.colTier'),
      render: (row: LicenseRecord) => (
        <div className="font-code-sm text-code-sm">
          {row.tier ?? '—'}
          <div className="text-outline">{row.plan ?? row.license_type}</div>
        </div>
      ),
    },
    {
      key: 'status',
      header: t('licensing.list.colStatus'),
      render: (row: LicenseRecord) => (
        <div className="flex flex-col gap-1">
          <Chip tone={statusTone(row.effective_status)}>{row.effective_status}</Chip>
          {row.revoked_reason ? (
            <span className="font-body-sm text-body-sm text-outline">
              {row.revoked_reason}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'expiry',
      header: t('licensing.list.colExpiry'),
      render: (row: LicenseRecord) => (
        <div className="font-code-sm text-code-sm">
          {row.expires_on ?? t('licensing.list.perpetual')}
          <div className="text-outline">
            {row.days_until_expiry === null || row.days_until_expiry === undefined
              ? '—'
              : t('licensing.list.daysLeft', { days: row.days_until_expiry })}
          </div>
        </div>
      ),
    },
    {
      key: 'actions',
      header: t('licensing.list.colActions'),
      render: (row: LicenseRecord) => (
        <Button type="button" variant="secondary" onClick={() => onSelect(row.license_key)}>
          {selectedKey === row.license_key
            ? t('licensing.list.inspected')
            : t('licensing.list.inspect')}
        </Button>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('licensing.list.title')}
        subtitle={t('licensing.list.subtitle')}
        actions={
          licenses.data
            ? t('licensing.list.count', {
                shown: licenses.data.licenses.length,
                total: licenses.data.total,
              })
            : undefined
        }
      />
      <div
        className="flex flex-wrap items-center gap-space-sm"
        role="group"
        aria-label={t('licensing.list.filterStatus')}
      >
        {STATUS_FILTERS.map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={status === (value === 'all' ? '' : value)}
            onClick={() => setStatus(value === 'all' ? '' : value)}
            className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
              status === (value === 'all' ? '' : value)
                ? 'bg-surface-container text-primary'
                : 'text-outline hover:bg-surface-container-high'
            }`}
          >
            {value === 'all' ? t('licensing.list.filterAll') : value}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap items-end gap-space-md">
        <label className="flex flex-col gap-1">
          <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
            {t('licensing.list.filterTier')}
          </span>
          <select
            value={tier}
            onChange={(event) => setTier(event.target.value)}
            className="min-w-40 rounded border border-outline-variant/60 bg-surface-container-lowest px-2 py-1.5 font-body-sm text-body-sm text-on-surface"
          >
            <option value="">{t('licensing.list.filterAllTiers')}</option>
            {(meta?.tiers ?? []).map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
            {t('licensing.list.filterType')}
          </span>
          <select
            value={licenseType}
            onChange={(event) => setLicenseType(event.target.value)}
            className="min-w-40 rounded border border-outline-variant/60 bg-surface-container-lowest px-2 py-1.5 font-body-sm text-body-sm text-on-surface"
          >
            <option value="">{t('licensing.list.filterAllTypes')}</option>
            {(meta?.license_types ?? []).map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
        <label className="flex min-w-56 flex-1 flex-col gap-1">
          <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
            {t('licensing.list.filterSearch')}
          </span>
          <input
            type="search"
            value={q}
            onChange={(event) => setQ(event.target.value)}
            placeholder={t('licensing.list.filterSearchHint')}
            className="rounded border border-outline-variant/60 bg-surface-container-lowest px-2 py-1.5 font-code-sm text-code-sm text-on-surface placeholder:text-outline"
          />
        </label>
      </div>
      <SectionBody query={licenses}>
        {(data: LicenseList) =>
          data.licenses.length === 0 ? (
            <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
              {t('licensing.list.empty')}
            </p>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-outline-variant/30">
              <DataTable
                columns={columns}
                rows={data.licenses}
                rowKey={(row) => row.license_key}
                caption={t('licensing.list.caption')}
              />
            </div>
          )
        }
      </SectionBody>
    </div>
  );
}
