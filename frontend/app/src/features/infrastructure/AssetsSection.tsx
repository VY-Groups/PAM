import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader } from '../../components';
import type {
  DiscoveredAsset,
  DiscoveryAssetType,
  DiscoveryPamStatus,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import { AdoptDialog } from './AdoptDialog';
import { OnboardDialog } from './OnboardDialog';
import { SectionBody } from './SectionBody';
import { useDiscoveryAccounts, useDiscoveryAssets, usePatchAsset } from './queries';
import { pamStatuses } from './schemas';

/** The PAM-status chips the contract's filter enum offers, `all` first. */
const PAM_FILTERS: readonly ('all' | DiscoveryPamStatus)[] = ['all', ...pamStatuses];

/**
 * The type chips: `all` plus the five families the legacy tabs
 * highlighted (contract enum values, raw and honest).
 */
const TYPE_FILTERS: readonly ('all' | DiscoveryAssetType)[] = [
  'all',
  'kubernetes',
  'linux',
  'database',
  'windows',
  'cloud',
];

/**
 * Discovered targets (F4 screen 7, plan §4 line 109 "Assets"). The
 * filter chips and the search drive real contract parameters
 * (`pam_status`, `type`, `q`) - the list refetches from the server, it
 * is never re-filtered client-side from a stale page. Row actions are
 * the contract's own writes: Ignore/Restore are `PATCH
 * /discovery/assets/{id}` pam_status flips and "Onboard to Vault Now"
 * adopts an unmanaged target; every result renders the server's own
 * message verbatim. Below the list, the privileged accounts ingested
 * at onboarding (`GET /discovery/accounts`).
 */
export function AssetsSection() {
  const { t } = useTranslation();

  const [pam, setPam] = useState<DiscoveryPamStatus | undefined>(undefined);
  const [type, setType] = useState<DiscoveryAssetType | undefined>(undefined);
  const [q, setQ] = useState('');

  const assets = useDiscoveryAssets({ pam, type, q });
  const accounts = useDiscoveryAccounts();
  const patchAsset = usePatchAsset();

  const [onboardOpen, setOnboardOpen] = useState(false);
  const [adoptTarget, setAdoptTarget] = useState<DiscoveredAsset | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  /** Ignore / Restore: the same PATCH, opposite pam_status. */
  const flipStatus = (asset: DiscoveredAsset, next: DiscoveryPamStatus) => {
    setStatus(null);
    setActionError(null);
    patchAsset.mutate(
      { assetId: asset.id, payload: { pam_status: next } },
      {
        onSuccess: (data) => setStatus(data.message),
        onError: (err) => setActionError(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('infrastructure.assets.title')}
        subtitle={t('infrastructure.assets.subtitle')}
        actions={
          <>
            {assets.data
              ? t('infrastructure.assets.count', {
                  shown: assets.data.assets.length,
                  total: assets.data.total,
                })
              : undefined}
            <Button type="button" icon="add_circle" onClick={() => setOnboardOpen(true)}>
              {t('infrastructure.actions.onboard')}
            </Button>
          </>
        }
      />
      <div className="flex flex-wrap items-center gap-space-sm">
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('infrastructure.assets.filterPam')}
        >
          {PAM_FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={(pam ?? 'all') === value}
              onClick={() => setPam(value === 'all' ? undefined : value)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                (pam ?? 'all') === value
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {value === 'all' ? t('infrastructure.assets.filterAll') : value}
            </button>
          ))}
        </div>
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('infrastructure.assets.filterType')}
        >
          {TYPE_FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={(type ?? 'all') === value}
              onClick={() => setType(value === 'all' ? undefined : value)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                (type ?? 'all') === value
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {value}
            </button>
          ))}
        </div>
        <input
          value={q}
          onChange={(event) => setQ(event.target.value)}
          placeholder={t('infrastructure.assets.searchPlaceholder')}
          aria-label={t('infrastructure.assets.searchPlaceholder')}
          className="w-56 rounded bg-surface-container-low p-2 font-body-sm text-body-sm text-on-surface focus:outline-none"
        />
      </div>
      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-code-sm text-code-sm text-tertiary"
      >
        {status ?? ''}
      </p>
      <p
        role="alert"
        className={`min-h-5 font-code-sm text-code-sm text-error${actionError ? '' : ' hidden'}`}
      >
        {actionError ?? ''}
      </p>
      <SectionBody query={assets}>
        {(data) =>
          data.assets.length === 0 ? (
            <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
              {t('infrastructure.assets.empty')}
            </p>
          ) : (
            <div className="flex flex-col gap-space-sm">
              {data.assets.map((asset) => (
                <div
                  key={asset.id}
                  className="flex flex-col gap-space-xs rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm"
                >
                  <div className="flex flex-wrap items-center gap-space-sm">
                    <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                      {asset.address}
                    </span>
                    {asset.hostname ? (
                      <span className="font-body-sm text-body-sm text-on-surface-variant">
                        {asset.hostname}
                      </span>
                    ) : null}
                    <Chip tone="inactive">{asset.asset_type}</Chip>
                    <Chip tone={asset.risk === 'LOW' ? 'inactive' : 'info'}>
                      {asset.risk}
                    </Chip>
                    <Chip tone={asset.pam_status === 'managed' ? 'info' : 'inactive'}>
                      {asset.pam_status}
                    </Chip>
                    <Chip tone="inactive">{`${asset.source}/${asset.method}`}</Chip>
                    <span className="ml-auto flex flex-wrap gap-space-sm">
                      {asset.pam_status === 'managed' ? (
                        <Button
                          type="button"
                          variant="secondary"
                          disabled={patchAsset.isPending}
                          onClick={() => flipStatus(asset, 'ignored')}
                        >
                          {t('infrastructure.actions.ignore')}
                        </Button>
                      ) : null}
                      {asset.pam_status === 'ignored' ? (
                        <Button
                          type="button"
                          variant="secondary"
                          disabled={patchAsset.isPending}
                          onClick={() => flipStatus(asset, 'managed')}
                        >
                          {t('infrastructure.actions.restore')}
                        </Button>
                      ) : null}
                      {asset.pam_status === 'unmanaged' ? (
                        <>
                          <Button
                            type="button"
                            variant="secondary"
                            disabled={patchAsset.isPending}
                            onClick={() => flipStatus(asset, 'managed')}
                          >
                            {t('infrastructure.actions.restore')}
                          </Button>
                          <Button
                            type="button"
                            variant="secondary"
                            onClick={() => setAdoptTarget(asset)}
                          >
                            {t('infrastructure.actions.adopt')}
                          </Button>
                        </>
                      ) : null}
                    </span>
                  </div>
                  {asset.ports.length > 0 ? (
                    <div className="flex flex-wrap items-center gap-1">
                      {asset.ports.map((p) => (
                        <Chip key={`${asset.id}:${p.port}:${p.proto}`} tone="inactive">
                          {`${p.port}/${p.proto}${p.service ? ` ${p.service}` : ''}`}
                        </Chip>
                      ))}
                    </div>
                  ) : null}
                  <div className="flex flex-wrap gap-space-sm font-code-sm text-code-sm text-outline">
                    <span>
                      {t('infrastructure.assets.vaultCount', {
                        count: asset.vault_count ?? 0,
                      })}
                    </span>
                    <span>{asset.recommended_policy}</span>
                    <span className="ml-auto">
                      {t('infrastructure.assets.lastSeen', {
                        at: formatTime(asset.last_seen) ?? '—',
                      })}
                    </span>
                  </div>
                  {asset.detail ? (
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {asset.detail}
                    </span>
                  ) : null}
                  {asset.notes ? (
                    <span className="font-code-sm text-code-sm text-outline">
                      {asset.notes}
                    </span>
                  ) : null}
                </div>
              ))}
            </div>
          )
        }
      </SectionBody>

      {/* Privileged accounts ingested at onboarding. */}
      <div className="mt-space-md flex flex-col gap-space-sm border-t border-outline-variant/20 pt-space-md">
        <div className="flex flex-wrap items-baseline justify-between gap-space-sm">
          <span className="font-label-md text-label-md text-on-surface">
            {t('infrastructure.accounts.title')}
          </span>
          <span className="font-body-sm text-body-sm text-on-surface-variant">
            {accounts.data
              ? t('infrastructure.accounts.count', {
                  shown: accounts.data.accounts.length,
                  total: accounts.data.total,
                })
              : ''}
          </span>
        </div>
        <SectionBody query={accounts}>
          {(data) =>
            data.accounts.length === 0 ? (
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                {t('infrastructure.accounts.empty')}
              </p>
            ) : (
              <div className="flex flex-col gap-1">
                {data.accounts.map((account) => (
                  <div
                    key={account.id}
                    className="flex flex-wrap items-center gap-space-sm border-b border-outline-variant/20 pb-1 last:border-b-0"
                  >
                    <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                      {account.username}
                    </span>
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {account.asset_address}
                    </span>
                    <Chip tone="inactive">{account.kind}</Chip>
                    <span className="ml-auto font-code-sm text-code-sm text-outline">
                      {account.source}
                    </span>
                  </div>
                ))}
              </div>
            )
          }
        </SectionBody>
      </div>

      <OnboardDialog
        open={onboardOpen}
        onOpenChange={setOnboardOpen}
        onStatus={setStatus}
      />
      <AdoptDialog
        open={adoptTarget !== null}
        onOpenChange={(open) => {
          if (!open) setAdoptTarget(null);
        }}
        target={
          adoptTarget === null ? null : { id: adoptTarget.id, address: adoptTarget.address }
        }
        onStatus={setStatus}
      />
    </div>
  );
}
