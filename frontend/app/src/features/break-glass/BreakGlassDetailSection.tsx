import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader, Value } from '../../components';
import { SectionBody } from './SectionBody';
import { useBreakGlassDetail } from './queries';
import type { BreakGlassRequest } from '../../api/generated/models';

/**
 * The request record (F4 screen 9): one emergency's full contract
 * picture - the reason and notes verbatim, the dual-approval
 * signatures with their timestamps, the denial, the release, the
 * recorded session and the close rotation - exactly what
 * `GET /break-glass/requests/{id}` answers. Read-only on purpose: the
 * table rows own the lifecycle actions (legacy console parity), this
 * panel only tells the truth about what happened - the close's
 * rotation outcome comes back on the close response and renders
 * verbatim on the page's status line.
 */
export function BreakGlassDetailSection({
  selectedId,
  onSelect,
}: {
  selectedId: number | null;
  onSelect: (id: number | null) => void;
}) {
  const { t } = useTranslation();
  const detail = useBreakGlassDetail(selectedId);

  if (selectedId === null) {
    return (
      <div className="flex flex-col gap-space-md">
        <SectionHeader title={t('breakGlass.detail.title')} />
        <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
          {t('breakGlass.detail.none')}
        </p>
      </div>
    );
  }

  const label = 'font-label-md text-label-md text-on-surface-variant';
  const line = 'font-code-sm text-code-sm text-on-surface';

  /** A labelled fact row: label above, verbatim value (or honest dash). */
  const fact = (key: string, value: string | null | undefined) => (
    <div key={key} className="flex flex-col gap-0.5">
      <span className={label}>{t(`breakGlass.detail.${key}`)}</span>
      <span className={line}>
        <Value value={value ?? null} />
      </span>
    </div>
  );

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('breakGlass.detail.title')}
        actions={
          <Button type="button" variant="secondary" onClick={() => onSelect(null)}>
            {t('breakGlass.detail.clear')}
          </Button>
        }
      />
      <SectionBody query={detail}>
        {(data) => {
          const request: BreakGlassRequest = data.request;
          const session = data.session;
          return (
            <div className="flex flex-col gap-space-md rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm">
              <div className="flex flex-wrap items-center gap-space-sm">
                <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                  {request.request_ref}
                </span>
                <Chip tone={request.severity === 'sev1' ? 'info' : 'inactive'}>
                  {request.severity}
                </Chip>
                <Chip
                  tone={
                    request.status === 'denied' || request.status === 'closed'
                      ? 'inactive'
                      : 'info'
                  }
                >
                  {request.status}
                </Chip>
                <Chip tone="inactive">{`mfa: ${request.mfa}`}</Chip>
                <span className="font-code-sm text-code-sm text-on-surface-variant">
                  {`${request.target} · ${request.protocol}`}
                </span>
              </div>

              <div className="flex flex-col gap-0.5">
                <span className={label}>{t('breakGlass.detail.reason')}</span>
                <span className="font-body-sm text-body-sm text-on-surface">
                  {request.reason}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-space-md lg:grid-cols-4">
                {fact('requestedBy', request.requested_by)}
                {fact('requestedAt', request.requested_at)}
                {fact('openedBy', request.opened_by ?? null)}
                {fact('openedAt', request.opened_at ?? null)}
              </div>

              {/* The dual-approval signatures, verbatim. */}
              <div className="flex flex-col gap-space-sm border-t border-outline-variant/30 pt-space-sm">
                <span className={label}>
                  {t('breakGlass.detail.approvals', {
                    signed: request.approvals_signed,
                    required: request.approvals_required,
                  })}
                </span>
                {request.approvals.length === 0 ? (
                  <span className={line}>{t('breakGlass.detail.noSignatures')}</span>
                ) : (
                  request.approvals.map((approval) => (
                    <div
                      key={approval.id}
                      className="flex flex-col gap-0.5 rounded bg-surface-container-low px-space-sm py-1"
                    >
                      <span className="font-code-sm text-code-sm font-semibold text-on-surface">
                        {`${approval.approver} · ${approval.decided_at}`}
                      </span>
                      <span className="font-body-sm text-body-sm text-on-surface-variant">
                        {approval.note !== ''
                          ? approval.note
                          : t('breakGlass.detail.noNote')}
                      </span>
                    </div>
                  ))
                )}
              </div>

              {/* Denial (when the request was turned down). */}
              {request.denied_at !== null && request.denied_at !== undefined ? (
                <div className="flex flex-col gap-0.5 border-t border-outline-variant/30 pt-space-sm">
                  <span className={label}>{t('breakGlass.detail.deniedHead')}</span>
                  <span
                    className={line}
                  >{`${request.denied_by ?? '—'} · ${request.denied_at}`}</span>
                  <span className="font-body-sm text-body-sm text-on-surface-variant">
                    {request.deny_note !== ''
                      ? request.deny_note
                      : t('breakGlass.detail.noNote')}
                  </span>
                </div>
              ) : null}

              {/* The recorded emergency session (once released). */}
              {session !== null ? (
                <div className="flex flex-col gap-space-sm border-t border-outline-variant/30 pt-space-sm">
                  <span className={label}>{t('breakGlass.detail.sessionHead')}</span>
                  <div className="flex flex-wrap items-center gap-space-sm">
                    <span className="font-code-sm text-code-sm font-semibold text-on-surface">
                      {session.session_ref}
                    </span>
                    <Chip tone={session.status === 'active' ? 'info' : 'inactive'}>
                      {session.status}
                    </Chip>
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {`${session.protocol} · ${session.target}`}
                    </span>
                    <span className="font-code-sm text-code-sm text-outline">
                      {session.controls.record
                        ? t('breakGlass.detail.recordingForced')
                        : t('breakGlass.detail.recordingOff')}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-space-md lg:grid-cols-4">
                    {fact('startedAt', session.started_at)}
                    {fact('endedAt', session.ended_at ?? null)}
                    {fact(
                      'duration',
                      session.duration_seconds !== null
                        ? `${session.duration_seconds}s`
                        : null,
                    )}
                  </div>
                </div>
              ) : null}

              {/* Close: review note + rotation outcome (contract-required note). */}
              {request.closed_at !== null && request.closed_at !== undefined ? (
                <div className="flex flex-col gap-space-sm border-t border-outline-variant/30 pt-space-sm">
                  <span className={label}>{t('breakGlass.detail.closedHead')}</span>
                  <span
                    className={line}
                  >{`${request.closed_by ?? '—'} · ${request.closed_at}`}</span>
                  <span className="font-body-sm text-body-sm text-on-surface-variant">
                    {request.review}
                  </span>
                </div>
              ) : null}
            </div>
          );
        }}
      </SectionBody>
    </div>
  );
}
