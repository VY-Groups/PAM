import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import { Button, KpiCard } from '../../components';
import { BreakGlassDetailSection } from './BreakGlassDetailSection';
import { BreakGlassListSection } from './BreakGlassListSection';
import { FileDialog } from './FileDialog';
import { ReleaseDialog } from './ReleaseDialog';
import { ReviewDialog } from './ReviewDialog';
import { useBreakGlassFactor, useBreakGlassStats } from './queries';

/**
 * Break-Glass Emergency Protocol (F4 screen 9, plan line 113: "Filing,
 * dual approval, recorded session") - the React successor of
 * `break_glass_emergency_protocol/code.html`.
 *
 * Parity: file an emergency (target/severity/protocol/reason with the
 * EMERGENCY-AUTHORIZE typing guard), the dual-approval signatures
 * (approve/deny post with the acting identity and the server's rules
 * judge it - the requester cannot sign their own emergency and a
 * second signature must come from someone else, both refusals rendered
 * verbatim), release the credential through the real vault checkout
 * (the section-20 factor gate reads `integrations/status`: enrolled
 * means the TOTP dialog, not enrolled opens directly - never a fake
 * challenge), the recorded session, and close with its
 * contract-required post-incident review note (the server answers the
 * rotation outcome, shown on the status line).
 *
 * The legacy console's editable acting-identity input stays: one
 * operator at one console plays requester and the two distinct
 * approvers, and every write records that input verbatim as `X-Actor`.
 */
export function BreakGlassPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();

  const stats = useBreakGlassStats();
  const factor = useBreakGlassFactor();

  /**
   * The acting identity, seeded with the signed-in principal; the
   * legacy console's editable input keeps its place (dual approval
   * needs two distinct names at one console).
   */
  const [actorInput, setActorInput] = useState('');
  const actor =
    actorInput.trim() !== '' ? actorInput.trim() : (whoami?.principal ?? 'console');

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [fileOpen, setFileOpen] = useState(false);
  const [releaseTarget, setReleaseTarget] = useState<{
    id: number;
    request_ref: string;
  } | null>(null);
  const [reviewTarget, setReviewTarget] = useState<{
    id: number;
    request_ref: string;
  } | null>(null);

  const onStatus = (message: string | null) => {
    setStatus(message);
    setError(null);
  };
  const onError = (message: string) => {
    setError(message);
    setStatus(null);
  };

  /** Backend-down gating (house pattern): the shared notice only when a
   * section's query actually failed on transport, never red on healthy. */
  const backendDownError =
    stats.error !== null && stats.error !== undefined && isBackendDown(stats.error)
      ? stats.error
      : factor.error !== null && factor.error !== undefined && isBackendDown(factor.error)
        ? factor.error
        : undefined;

  const openEmergencies = stats.data?.open_emergencies ?? null;
  const mfaGate = factor.data?.mfa?.gate ?? null;

  const input =
    'w-full rounded bg-surface-container-low p-2 font-body-sm text-body-sm text-on-surface focus:outline-none';
  const label = 'font-label-md text-label-md text-on-surface-variant';

  return (
    <div className="flex flex-col gap-space-lg">
      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {/* The legacy critical banner: static claims + the live factor state. */}
      <div className="flex items-center gap-2 rounded-lg border border-error/30 bg-error-container/70 px-space-lg py-2.5 font-code-sm text-code-sm text-on-error-container">
        <span className="material-symbols-outlined text-[18px]" aria-hidden="true">
          warning
        </span>
        <span>
          {t('breakGlass.page.banner')}{' '}
          <span className="font-semibold">
            {t('breakGlass.page.bannerMfa', { state: mfaGate ?? '—' })}
          </span>
        </span>
      </div>

      {/* Header: title, live open-emergency chip, the filing button. */}
      <div className="flex flex-wrap items-end justify-between gap-space-lg">
        <div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface">
            {t('breakGlass.page.title')}
          </h1>
          <p className="mt-1 max-w-3xl font-body-md text-body-md text-on-surface-variant">
            {t('breakGlass.page.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-space-sm">
          {openEmergencies !== null ? (
            <span
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider ${
                openEmergencies > 0
                  ? 'bg-error-container text-error'
                  : 'bg-surface-container text-on-surface-variant'
              }`}
              role="status"
            >
              {openEmergencies === 1
                ? t('breakGlass.page.openEmergency', { count: openEmergencies })
                : t('breakGlass.page.openEmergencies', { count: openEmergencies })}
            </span>
          ) : null}
          <Button
            type="button"
            variant="destructive"
            icon="lock_open"
            onClick={() => setFileOpen(true)}
          >
            {t('breakGlass.page.fileButton')}
          </Button>
        </div>
      </div>

      {/* The honest status line (aria-live) for every direct action. */}
      <div className="flex flex-col gap-1">
        <p
          role="status"
          aria-live="polite"
          className="font-body-sm text-body-sm text-on-surface"
        >
          {status ?? ''}
        </p>
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {error ?? ''}
        </p>
      </div>

      {/* KPI quad: the real aggregates straight from /break-glass/stats. */}
      <div className="grid grid-cols-1 gap-space-md md:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label={t('breakGlass.page.kpiTotal')}
          value={stats.data?.requests.total ?? null}
          footer={t('breakGlass.page.kpiTotalFoot')}
        />
        <KpiCard
          label={t('breakGlass.page.kpiPending')}
          value={stats.data?.requests.pending ?? null}
          footer={t('breakGlass.page.kpiPendingFoot', {
            outstanding: stats.data?.approvals.outstanding ?? 0,
          })}
          accent="primary-container"
        />
        <KpiCard
          label={t('breakGlass.page.kpiOpen')}
          value={openEmergencies}
          footer={t('breakGlass.page.kpiOpenFoot')}
          accent="error"
        />
        <KpiCard
          label={t('breakGlass.page.kpiLastUnseal')}
          value={stats.data?.last_opened_at ?? null}
          footer={t('breakGlass.page.kpiLastUnsealFoot')}
          accent="tertiary"
        />
      </div>

      {/* The registry plus the acting-identity rail (legacy parity). */}
      <div className="grid grid-cols-1 gap-space-lg xl:grid-cols-[minmax(0,3fr)_minmax(24rem,1fr)]">
        <BreakGlassListSection
          actor={actor}
          onSelect={setSelectedId}
          mfaConfigured={factor.data?.mfa?.configured ?? false}
          onRelease={setReleaseTarget}
          onReview={setReviewTarget}
          onStatus={onStatus}
          onError={onError}
        />

        <div className="flex flex-col gap-space-md">
          {/* Acting identity: recorded verbatim as X-Actor on every write. */}
          <div className="flex flex-col gap-space-sm rounded-xl border border-outline-variant/40 bg-surface-container-lowest p-space-lg">
            <span className="font-code-sm text-code-sm uppercase tracking-wider text-outline">
              {t('breakGlass.rail.actorHead')}
            </span>
            <label className="flex flex-col gap-1">
              <span className={label}>{t('breakGlass.rail.actorLabel')}</span>
              <input
                value={actorInput}
                onChange={(event) => setActorInput(event.target.value)}
                maxLength={64}
                placeholder={whoami?.principal ?? 'console'}
                className={input}
              />
            </label>
            <p className="font-code-sm text-code-sm leading-relaxed text-outline">
              {t('breakGlass.rail.actorHint', { actor })}
            </p>
          </div>

          {/* The five-step dual-approval process (static explanation). */}
          <div className="flex flex-col gap-space-sm rounded-xl border border-outline-variant/40 bg-surface-container-lowest p-space-lg">
            <span className="font-code-sm text-code-sm uppercase tracking-wider text-outline">
              {t('breakGlass.rail.processHead')}
            </span>
            <ol className="flex list-decimal flex-col gap-1 pl-5 font-body-sm text-body-sm text-on-surface">
              <li>{t('breakGlass.rail.step1')}</li>
              <li>{t('breakGlass.rail.step2')}</li>
              <li>{t('breakGlass.rail.step3')}</li>
              <li>{t('breakGlass.rail.step4')}</li>
              <li>{t('breakGlass.rail.step5')}</li>
            </ol>
            <p className="border-t border-outline-variant/40 pt-space-sm font-code-sm text-code-sm text-outline">
              {t('breakGlass.rail.mfaLine', { state: mfaGate ?? '—' })}
            </p>
          </div>

          {/* The safeguards (static explanation, legacy parity). */}
          <div className="flex flex-col gap-space-sm rounded-xl border border-outline-variant/40 bg-surface-container-lowest p-space-lg">
            <span className="font-code-sm text-code-sm uppercase tracking-wider text-outline">
              {t('breakGlass.rail.safeguardsHead')}
            </span>
            <ul className="flex flex-col gap-1 font-body-sm text-body-sm text-on-surface">
              <li>{t('breakGlass.rail.safeguard1')}</li>
              <li>{t('breakGlass.rail.safeguard2')}</li>
              <li>{t('breakGlass.rail.safeguard3')}</li>
              <li>{t('breakGlass.rail.safeguard4')}</li>
              <li>{t('breakGlass.rail.safeguard5')}</li>
            </ul>
          </div>
        </div>
      </div>

      {/* The selected request's full record (read-only). */}
      <BreakGlassDetailSection selectedId={selectedId} onSelect={setSelectedId} />

      <FileDialog
        open={fileOpen}
        onOpenChange={setFileOpen}
        onStatus={onStatus}
        actor={actor}
      />
      <ReleaseDialog
        open={releaseTarget !== null}
        onOpenChange={(next) => {
          if (!next) setReleaseTarget(null);
        }}
        onStatus={onStatus}
        requestId={releaseTarget?.id ?? null}
        actor={actor}
      />
      <ReviewDialog
        open={reviewTarget !== null}
        onOpenChange={(next) => {
          if (!next) setReviewTarget(null);
        }}
        onStatus={onStatus}
        requestId={reviewTarget?.id ?? null}
        actor={actor}
      />
    </div>
  );
}
