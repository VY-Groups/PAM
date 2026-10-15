import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import { Button, Chip, KpiCard } from '../../components';
import { InviteDialog } from './InviteDialog';
import { SeedCard, type VendorSeed } from './SeedCard';
import { VendorDetailSection } from './VendorDetailSection';
import { VendorListSection } from './VendorListSection';
import { useVendors } from './queries';

/**
 * Vendor Access (F4 screen 8, plan line 114: "Chain steps, invite,
 * scoped requests") - the React successor of
 * `vendor_access_third_party_lifecycle/code.html`.
 *
 * Parity: the vendor registry with its status/q contract filters, the
 * one-time invite (account row + TOTP seed shown exactly once), the
 * four-step chain (real TOTP verify, NDA record, real §20 ITSM ticket
 * check, approve with the server's missing-steps refusal verbatim),
 * deny/revoke, the scoped request against a real vault item and the
 * full lifecycle trail. Every number and message renders from the API;
 * absent data is the honest em-dash or an honest empty line. The
 * contract's PATCH (contact/scope edit) stays out: the legacy screen
 * has no edit surface, so there is no parity bar to reach (documented
 * deferral, like zone binding on screen 7).
 */
export function VendorPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  const actor = whoami?.principal ?? 'console';

  const vendors = useVendors({ q: '' });
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [seed, setSeed] = useState<VendorSeed | null>(null);

  const backendDownError =
    vendors.error !== null && vendors.error !== undefined && isBackendDown(vendors.error)
      ? vendors.error
      : undefined;

  /* -------------------------------------------------------------- kpis */
  const rows = vendors.data?.vendors ?? [];
  const invited = rows.filter((v) => v.status === 'invited').length;
  const approved = rows.filter((v) => v.status === 'approved').length;
  const closed = rows.filter(
    (v) => v.status !== 'invited' && v.status !== 'approved',
  ).length;

  const kpis = (
    <div className="grid grid-cols-1 gap-space-md sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t('vendor.kpis.accounts')}
        value={vendors.data?.total ?? null}
        footer={t('vendor.kpis.accountsFooter')}
        accent="primary"
      />
      <KpiCard
        label={t('vendor.kpis.invited')}
        value={vendors.data ? invited : null}
        footer={t('vendor.kpis.invitedFooter')}
        accent="tertiary"
      />
      <KpiCard
        label={t('vendor.kpis.approved')}
        value={vendors.data ? approved : null}
        footer={t('vendor.kpis.approvedFooter')}
        accent="primary-container"
      />
      <KpiCard
        label={t('vendor.kpis.closed')}
        value={vendors.data ? closed : null}
        footer={t('vendor.kpis.closedFooter')}
        accent="tertiary"
      />
    </div>
  );

  /* ------------------------------------------------------------- render */
  return (
    <div className="flex flex-col gap-space-lg">
      <div className="flex flex-col gap-space-md">
        <div className="flex flex-wrap items-center gap-space-sm">
          <Chip>{t('vendor.kicker')}</Chip>
          <span className="font-code-sm text-code-sm text-on-surface-variant">
            {t('vendor.line')}{' '}
            <span className="font-semibold text-on-surface">
              {vendors.data
                ? t('vendor.lineValue', {
                    total: vendors.data.total,
                    invited,
                    approved,
                  })
                : '—'}
            </span>
          </span>
          <span className="ml-auto">
            <Button type="button" icon="person_add" onClick={() => setInviteOpen(true)}>
              {t('vendor.actions.invite')}
            </Button>
          </span>
        </div>
        <div className="flex max-w-3xl flex-col gap-space-xs">
          <h1 className="font-headline-xl text-headline-xl font-bold text-on-surface">
            {t('vendor.title')}
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant">
            {t('vendor.subtitle')}
          </p>
        </div>
      </div>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {kpis}

      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-code-sm text-code-sm text-tertiary"
      >
        {status ?? ''}
      </p>

      {seed !== null ? <SeedCard seed={seed} onHide={() => setSeed(null)} /> : null}

      <VendorListSection
        actor={actor}
        selectedId={selectedId}
        onSelect={setSelectedId}
        onSeed={setSeed}
      />
      <VendorDetailSection actor={actor} vendorId={selectedId} onSelect={setSelectedId} />

      <InviteDialog
        open={inviteOpen}
        onOpenChange={setInviteOpen}
        onStatus={setStatus}
        onSeed={setSeed}
        actor={actor}
      />
    </div>
  );
}
