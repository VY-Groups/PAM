import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader } from '../../components';
import { formatRelative, formatTime } from '../../lib/format';
import { DenyDialog } from './DenyDialog';
import { MfaDialog } from './MfaDialog';
import { NdaDialog } from './NdaDialog';
import { RevokeDialog } from './RevokeDialog';
import { RequestDialog } from './RequestDialog';
import { SectionBody } from './SectionBody';
import { TicketDialog } from './TicketDialog';
import { useVendorApprove, useVendorDetail } from './queries';

/** Read a field of the loosely-typed verification/detail records. */
function str(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  return null;
}

/**
 * The selected vendor's §13 dashboard (F4 screen 8): the four chain
 * steps with their timestamps and the server's own ITSM verification
 * detail verbatim, the access scope, the real scoped grants and the
 * full lifecycle trail - all from `GET /vendors/{id}`. The chain
 * actions mirror the legacy screen exactly: the three step buttons and
 * Approve/Deny while the account sits `invited` (Approve stays enabled
 * so the server's 409 `details.missing` refusal renders verbatim - the
 * chain cannot be short-cut client side), Revoke and File request once
 * `approved`.
 */
export function VendorDetailSection({
  actor,
  vendorId,
  onSelect,
}: {
  actor: string;
  vendorId: number | null;
  onSelect: (id: number | null) => void;
}) {
  const { t } = useTranslation();
  const vendor = useVendorDetail(vendorId);
  const vendorApprove = useVendorApprove();

  const [mfaOpen, setMfaOpen] = useState(false);
  const [ndaOpen, setNdaOpen] = useState(false);
  const [ticketOpen, setTicketOpen] = useState(false);
  const [denyOpen, setDenyOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [requestOpen, setRequestOpen] = useState(false);
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  if (vendorId === null) {
    return (
      <div className="flex flex-col gap-space-md">
        <SectionHeader title={t('vendor.detail.title')} />
        <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
          {t('vendor.detail.none')}
        </p>
      </div>
    );
  }

  /** Step 4: the server answers 200 or names the missing steps (409). */
  const approve = () => {
    setActionStatus(null);
    setActionError(null);
    vendorApprove.mutate(
      { actor, vendorId },
      {
        onSuccess: (data) => setActionStatus(data.message),
        onError: (err) => setActionError(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  const clear = () => {
    setActionStatus(null);
    setActionError(null);
    onSelect(null);
  };

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('vendor.detail.title')}
        actions={
          <Button type="button" variant="secondary" onClick={clear}>
            {t('vendor.detail.clear')}
          </Button>
        }
      />
      <SectionBody query={vendor}>
        {(data) => {
          const tv = data.ticket_verification;
          const tvDetail = str(tv?.detail);
          return (
            <>
              <div className="flex flex-wrap items-center gap-space-sm">
                <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                  {data.name}
                </span>
                <Chip tone={data.status === 'approved' ? 'info' : 'inactive'}>
                  {data.status}
                </Chip>
                {data.contact ? (
                  <span className="font-body-sm text-body-sm text-on-surface-variant">
                    {data.contact}
                  </span>
                ) : null}
              </div>

              {/* The four chain steps with their real timestamps. */}
              <div className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm">
                <span className="font-label-md text-label-md text-on-surface">
                  {t('vendor.detail.stepsTitle')}
                </span>
                <div className="flex flex-wrap items-center gap-space-sm">
                  <Chip tone={data.steps.mfa === 'verified' ? 'info' : 'inactive'}>
                    {`mfa: ${data.steps.mfa}`}
                  </Chip>
                  <span className="font-code-sm text-code-sm text-outline">
                    {data.mfa_verified_at
                      ? t('vendor.detail.verifiedAt', {
                          at: formatTime(data.mfa_verified_at) ?? '—',
                        })
                      : t('vendor.detail.notYet')}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-space-sm">
                  <Chip tone={data.steps.nda === 'signed' ? 'info' : 'inactive'}>
                    {`nda: ${data.steps.nda}`}
                  </Chip>
                  <span className="font-code-sm text-code-sm text-outline">
                    {data.nda?.signed_at
                      ? t('vendor.detail.ndaLine', {
                          ref: data.nda.ref ?? '—',
                          at: formatTime(data.nda.signed_at) ?? '—',
                        })
                      : t('vendor.detail.notYet')}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-space-sm">
                  <Chip tone={data.steps.ticket === 'verified' ? 'info' : 'inactive'}>
                    {`ticket: ${data.steps.ticket}`}
                  </Chip>
                  <span className="font-code-sm text-code-sm text-outline">
                    {tvDetail !== null
                      ? t('vendor.detail.ticketLine', {
                          ticket: data.ticket ?? '—',
                          detail: tvDetail,
                        })
                      : t('vendor.detail.notYet')}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-space-sm">
                  <Chip tone={data.steps.approval === 'approved' ? 'info' : 'inactive'}>
                    {`approval: ${data.steps.approval}`}
                  </Chip>
                  <span className="font-code-sm text-code-sm text-outline">
                    {data.approved_at
                      ? t('vendor.detail.approvalLine', {
                          by: data.approved_by ?? '—',
                          at: formatTime(data.approved_at) ?? '—',
                        })
                      : data.denied_reason !== null && data.denied_reason !== undefined
                        ? t('vendor.list.reason', { reason: data.denied_reason })
                        : t('vendor.detail.notYet')}
                  </span>
                </div>
              </div>

              {/* Chain actions: exactly what the account's state allows. */}
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
              <div className="flex flex-wrap items-center gap-space-sm">
                {data.status === 'invited' ? (
                  <>
                    <Button type="button" onClick={() => setMfaOpen(true)}>
                      {t('vendor.actions.verifyMfa')}
                    </Button>
                    <Button type="button" onClick={() => setNdaOpen(true)}>
                      {t('vendor.actions.recordNda')}
                    </Button>
                    <Button type="button" onClick={() => setTicketOpen(true)}>
                      {t('vendor.actions.verifyTicket')}
                    </Button>
                    <Button
                      type="button"
                      disabled={vendorApprove.isPending}
                      onClick={approve}
                    >
                      {t('vendor.actions.approve')}
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => setDenyOpen(true)}
                    >
                      {t('vendor.actions.deny')}
                    </Button>
                  </>
                ) : null}
                {data.status === 'approved' ? (
                  <>
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => setRevokeOpen(true)}
                    >
                      {t('vendor.actions.revoke')}
                    </Button>
                    <Button type="button" onClick={() => setRequestOpen(true)}>
                      {t('vendor.actions.request')}
                    </Button>
                  </>
                ) : null}
              </div>

              {/* Access scope: allowed/denied targets, window, recording. */}
              <div className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm">
                <span className="font-label-md text-label-md text-on-surface">
                  {t('vendor.detail.accessTitle')}
                </span>
                <div className="flex flex-wrap items-center gap-1">
                  <span className="font-code-sm text-code-sm text-outline">
                    {t('vendor.detail.allowedLabel')}
                  </span>
                  {data.access.allowed.length === 0 ? (
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('vendor.detail.noTargets')}
                    </span>
                  ) : (
                    data.access.allowed.map((target) => (
                      <Chip key={`allowed:${target}`} tone="info">
                        {target}
                      </Chip>
                    ))
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  <span className="font-code-sm text-code-sm text-outline">
                    {t('vendor.detail.deniedLabel')}
                  </span>
                  {data.access.denied.length === 0 ? (
                    <span className="font-body-sm text-body-sm text-on-surface-variant">
                      {t('vendor.detail.noTargets')}
                    </span>
                  ) : (
                    data.access.denied.map((target) => (
                      <Chip key={`denied:${target}`} tone="inactive">
                        {target}
                      </Chip>
                    ))
                  )}
                </div>
                <div className="flex flex-wrap gap-space-sm font-code-sm text-code-sm text-outline">
                  <span>
                    {data.access.window !== null
                      ? t('vendor.list.window', { window: data.access.window })
                      : t('vendor.list.anyHour')}
                  </span>
                  <span>
                    {data.access.recording
                      ? t('vendor.detail.recordingOn')
                      : t('vendor.detail.recordingOff')}
                  </span>
                  <span>
                    {data.access.expires_at !== null
                      ? t('vendor.list.expiresAt', { at: data.access.expires_at })
                      : t('vendor.list.noExpiry')}
                  </span>
                </div>
              </div>

              {/* Real scoped grants filed by this vendor. */}
              <div className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm">
                <span className="font-label-md text-label-md text-on-surface">
                  {t('vendor.detail.grantsTitle')}
                </span>
                <span className="font-body-sm text-body-sm text-on-surface-variant">
                  {t('vendor.detail.grantsCount', { count: data.request_count })}
                </span>
                {data.requests.length === 0 ? (
                  <span className="font-body-sm text-body-sm text-on-surface-variant">
                    {t('vendor.detail.noGrants')}
                  </span>
                ) : (
                  data.requests.map((request) => (
                    <div key={request.id} className="flex flex-col gap-space-xs">
                      <div className="flex flex-wrap items-center gap-space-sm">
                        <span className="font-code-sm text-code-sm text-outline">
                          {`#${request.id}`}
                        </span>
                        <Chip tone={request.status === 'approved' ? 'info' : 'inactive'}>
                          {request.status}
                        </Chip>
                        <span className="font-body-sm text-body-sm text-on-surface">
                          {t('vendor.detail.grantRow', {
                            item: request.item_id,
                            risk: request.risk.level,
                            minutes: request.minutes,
                          })}
                        </span>
                        <span className="ml-auto font-body-sm text-body-sm text-outline">
                          {formatRelative(request.created_at) ?? '—'}
                        </span>
                      </div>
                      <span className="font-code-sm text-code-sm text-on-surface-variant">
                        {t('vendor.detail.grantReason', {
                          requester: request.requester,
                          reason: request.reason,
                        })}
                      </span>
                    </div>
                  ))
                )}
              </div>

              {/* The full §13 lifecycle trail. */}
              <div className="flex flex-col gap-space-sm rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm">
                <span className="font-label-md text-label-md text-on-surface">
                  {t('vendor.detail.trailTitle')}
                </span>
                {data.events.length === 0 ? (
                  <span className="font-body-sm text-body-sm text-on-surface-variant">
                    {t('vendor.detail.trailEmpty')}
                  </span>
                ) : (
                  data.events.map((event) => (
                    <div
                      key={event.id}
                      className="flex flex-col gap-space-xs border-b border-outline-variant/20 pb-1 last:border-b-0"
                    >
                      <div className="flex flex-wrap items-center gap-space-sm">
                        <span className="font-code-sm text-code-sm text-outline">
                          {`#${event.id}`}
                        </span>
                        <Chip
                          tone={
                            event.action.includes('refused') ||
                            event.action.includes('failed') ||
                            event.action === 'denied' ||
                            event.action === 'revoked' ||
                            event.action === 'expired'
                              ? 'inactive'
                              : 'info'
                          }
                        >
                          {event.action}
                        </Chip>
                        <span className="font-body-sm text-body-sm text-on-surface-variant">
                          {event.subject}
                        </span>
                        <span className="ml-auto font-body-sm text-body-sm text-outline">
                          {event.actor} · {formatRelative(event.created_at) ?? '—'}
                        </span>
                      </div>
                      {event.detail && typeof event.detail === 'object' ? (
                        <span className="font-code-sm text-code-sm text-outline">
                          {Object.entries(event.detail)
                            .slice(0, 2)
                            .map(
                              ([key, value]) =>
                                `${key}=${
                                  typeof value === 'object' && value !== null
                                    ? JSON.stringify(value)
                                    : String(value)
                                }`,
                            )
                            .join('  ')}
                        </span>
                      ) : null}
                    </div>
                  ))
                )}
              </div>

              <MfaDialog
                open={mfaOpen}
                onOpenChange={setMfaOpen}
                onStatus={setActionStatus}
                vendorId={data.id}
                actor={actor}
              />
              <NdaDialog
                open={ndaOpen}
                onOpenChange={setNdaOpen}
                onStatus={setActionStatus}
                vendorId={data.id}
                actor={actor}
              />
              <TicketDialog
                open={ticketOpen}
                onOpenChange={setTicketOpen}
                onStatus={setActionStatus}
                vendorId={data.id}
                actor={actor}
              />
              <DenyDialog
                open={denyOpen}
                onOpenChange={setDenyOpen}
                onStatus={setActionStatus}
                vendorId={data.id}
                actor={actor}
              />
              <RevokeDialog
                open={revokeOpen}
                onOpenChange={setRevokeOpen}
                onStatus={setActionStatus}
                vendorId={data.id}
                actor={actor}
              />
              <RequestDialog
                open={requestOpen}
                onOpenChange={setRequestOpen}
                onStatus={setActionStatus}
                vendorId={data.id}
                actor={actor}
              />
            </>
          );
        }}
      </SectionBody>
    </div>
  );
}
