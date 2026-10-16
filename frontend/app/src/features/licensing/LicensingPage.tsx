import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { Button, Chip, KpiCard, NotConnected, SectionHeader } from '../../components';
import type { LicenseRecord } from '../../api/generated/models';
import { FileDialog } from './FileDialog';
import { LicenseDetailSection } from './LicenseDetailSection';
import { LicenseListSection } from './LicenseListSection';
import { ImportDialog } from './ImportDialog';
import { RevokeDialog } from './RevokeDialog';
import { ValidateDialog } from './ValidateDialog';
import { useLicenseMeta, useLicensingOverview, useRestoreLicense } from './queries';

/**
 * Enterprise Licensing, Tier Entitlements & Node Quotas (F4 screen 10) -
 * the React successor of
 * `enterprise_licensing_tier_entitlements_node_quotas/code.html`
 * (the nav's recorded legacyHref; the strangler keeps the legacy URL
 * served until this route is the canonical destination).
 *
 * Parity with the legacy sections: the license registry with real
 * filters (status/tier/type/q as contract parameters), the KPI quad
 * from `/api/v1/overview`, the entitlements + quota meters + pool
 * breakdown + payload signature + activity timeline of the selected
 * license, and the offline air-gap ingestion (import), offline-parity
 * validation, signed-file viewing and the revoke/restore lifecycle -
 * every write answers the server's own message verbatim.
 */
export function LicensingPage() {
  const { t } = useTranslation();

  const overview = useLicensingOverview();
  const meta = useLicenseMeta();
  const restoreLicense = useRestoreLicense();

  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [validateOpen, setValidateOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<LicenseRecord | null>(null);
  const [fileTarget, setFileTarget] = useState<LicenseRecord | null>(null);

  const backendDown = overview.isError && isBackendDown(overview.error);

  /** Restore posts directly; the server answers its message verbatim. */
  const restore = (license: LicenseRecord) => {
    setStatus(null);
    setError(null);
    restoreLicense.mutate(license.license_key, {
      onSuccess: (data) => setStatus(data.message),
      onError: (err) => setError(err instanceof Error ? err.message : String(err)),
    });
  };

  const licenses = overview.data?.licenses;

  return (
    <div className="flex flex-col gap-space-lg" data-testid="licensing-page">
      <SectionHeader
        title={t('licensing.page.title')}
        subtitle={t('licensing.page.subtitle')}
        actions={
          <Button type="button" onClick={() => setImportOpen(true)}>
            {t('licensing.page.importCta')}
          </Button>
        }
      />
      {backendDown ? (
        <BackendDownNotice
          body={t('errors.backendDown')}
          error={overview.isError ? overview.error : undefined}
        />
      ) : null}
      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-body-sm text-body-sm text-on-surface-variant"
      >
        {status}
      </p>
      {error !== null ? (
        <p role="alert" className="min-h-5 font-body-sm text-body-sm text-error">
          {error}
        </p>
      ) : null}

      {/* KPI quad: the overview aggregates, exactly the contract's block.
          Loading and failure both read the honest em-dash - a dead backend
          must never render as a zeroed quad (brief §3.2). */}
      <div className="grid gap-space-md sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label={t('licensing.kpi.total')}
          value={overview.data ? String(licenses?.total ?? 0) : '—'}
        />
        <KpiCard
          label={t('licensing.kpi.active')}
          value={overview.data ? String(licenses?.active ?? 0) : '—'}
        />
        <KpiCard
          label={t('licensing.kpi.expiring')}
          value={overview.data ? String(licenses?.expiring_soon ?? 0) : '—'}
        />
        <KpiCard
          label={t('licensing.kpi.revoked')}
          value={overview.data ? String(licenses?.revoked ?? 0) : '—'}
        />
      </div>
      {licenses?.by_tier ? (
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('licensing.kpi.byTier')}
        >
          <span className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
            {t('licensing.kpi.byTier')}
          </span>
          {Object.entries(licenses.by_tier).map(([tier, count]) => (
            <Chip key={tier} tone="info">
              {tier}: {String(count)}
            </Chip>
          ))}
        </div>
      ) : null}

      {/* Registry + contract catalog rail (the legacy two-column body). */}
      <div className="grid gap-space-lg xl:grid-cols-3">
        <div className="flex flex-col gap-space-lg xl:col-span-2">
          <LicenseListSection
            meta={meta.data}
            selectedKey={selectedKey}
            onSelect={setSelectedKey}
          />
        </div>
        <aside
          className="flex flex-col gap-space-lg"
          aria-label={t('licensing.rail.title')}
        >
          <div className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 p-space-md">
            <h3 className="font-title-sm text-title-sm text-on-surface">
              {t('licensing.rail.catalog')}
            </h3>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('licensing.rail.catalogHint')}
            </p>
            {meta.data ? (
              <dl className="flex flex-col gap-2">
                <div>
                  <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.rail.tiers')}
                  </dt>
                  <dd className="font-body-sm text-body-sm text-on-surface">
                    {meta.data.tiers.join(' · ')}
                  </dd>
                </div>
                <div>
                  <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.rail.types')}
                  </dt>
                  <dd className="font-body-sm text-body-sm text-on-surface">
                    {meta.data.license_types.join(' · ')}
                  </dd>
                </div>
                <div>
                  <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.rail.algorithms')}
                  </dt>
                  <dd className="font-body-sm text-body-sm text-on-surface">
                    {meta.data.algorithms.join(' · ')}
                  </dd>
                </div>
                <div>
                  <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.rail.formats')}
                  </dt>
                  <dd className="font-body-sm text-body-sm text-on-surface">
                    {meta.data.formats.join(' · ')}
                  </dd>
                </div>
                <div>
                  <dt className="font-label-badge text-label-badge uppercase tracking-wider text-outline">
                    {t('licensing.rail.modules')}
                  </dt>
                  <dd className="font-body-sm text-body-sm text-on-surface">
                    {t('licensing.rail.modulesCount', {
                      count: meta.data.modules.length,
                    })}
                  </dd>
                </div>
              </dl>
            ) : meta.isPending ? (
              <p className="font-body-sm text-body-sm text-outline">
                {t('licensing.states.loading')}
              </p>
            ) : meta.isError && isBackendDown(meta.error) ? (
              <NotConnected />
            ) : (
              <p role="alert" className="font-body-sm text-body-sm text-error">
                {t('licensing.states.error', {
                  message:
                    meta.error instanceof Error ? meta.error.message : String(meta.error),
                })}
              </p>
            )}
          </div>
          <div className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 p-space-md">
            <h3 className="font-title-sm text-title-sm text-on-surface">
              {t('licensing.rail.airgapTitle')}
            </h3>
            <ol className="flex list-decimal flex-col gap-1 pl-4 font-body-sm text-body-sm text-on-surface-variant">
              <li>{t('licensing.rail.airgapStep1')}</li>
              <li>{t('licensing.rail.airgapStep2')}</li>
              <li>{t('licensing.rail.airgapStep3')}</li>
              <li>{t('licensing.rail.airgapStep4')}</li>
            </ol>
            <p className="font-body-sm text-body-sm text-outline">
              {t('licensing.rail.airgapNote')}
            </p>
            <div className="mt-1 flex flex-wrap gap-1.5">
              <Button type="button" variant="secondary" onClick={() => setImportOpen(true)}>
                {t('licensing.page.importCta')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => setValidateOpen(true)}
              >
                {t('licensing.page.validateCta')}
              </Button>
            </div>
          </div>
        </aside>
      </div>

      <LicenseDetailSection
        licenseKey={selectedKey}
        meta={meta.data}
        onRevoke={(license) => setRevokeTarget(license)}
        onRestore={restore}
        onShowFile={(license) => setFileTarget(license)}
        onValidate={() => setValidateOpen(true)}
        onStatus={setStatus}
      />

      <ImportDialog open={importOpen} onOpenChange={setImportOpen} onStatus={setStatus} />
      <ValidateDialog open={validateOpen} onOpenChange={setValidateOpen} />
      <RevokeDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
        onStatus={setStatus}
        license={revokeTarget}
      />
      <FileDialog
        open={fileTarget !== null}
        onOpenChange={(open) => {
          if (!open) setFileTarget(null);
        }}
        license={fileTarget}
      />
    </div>
  );
}
