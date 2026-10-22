import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, DataTable, SectionHeader } from '../../components';
import type { BreakGlassRequest } from '../../api/generated/models';
import { ACTION_OPS, canOperate } from '../../app/guards/RoleGate';
import { useAuth } from '../../app/providers/useAuth';
import { SectionBody } from './SectionBody';
import {
  useApproveBreakGlass,
  useBreakGlassList,
  useDenyBreakGlass,
  useOpenBreakGlass,
} from './queries';
import { breakGlassStatuses } from './schemas';

/** The status chips the contract's filter enum offers, `all` first. */
const STATUS_FILTERS: readonly ('all' | (typeof breakGlassStatuses)[number])[] = [
  'all',
  ...breakGlassStatuses,
];

/** In-flight states read `info`, terminal ones read `inactive`. */
function statusTone(status: BreakGlassRequest['status']): 'info' | 'inactive' {
  return status === 'pending' || status === 'approved' || status === 'used'
    ? 'info'
    : 'inactive';
}

/** The highest severity reads marked; the routine ones stay quiet. */
function severityTone(severity: BreakGlassRequest['severity']): 'info' | 'inactive' {
  return severity === 'sev1' ? 'info' : 'inactive';
}

/**
 * The emergency request registry (F4 screen 9, plan line 113 "Filing,
 * dual approval, recorded session"). The status chips drive a real
 * contract parameter (`status` by equality) - the list refetches from
 * the server, it is never re-filtered client-side from a stale page.
 * Row actions mirror the legacy console exactly: approve and deny post
 * directly (the server judges the acting identity - the requester
 * cannot sign their own emergency and a second signature must come
 * from someone else, both refusals rendered verbatim on the page's
 * status line), "Open (unseal)" posts directly while no factor is
 * enrolled and routes through the MFA release dialog when one is, and
 * "Close + review" always opens the required-note dialog.
 */
export function BreakGlassListSection({
  actor,
  onSelect,
  mfaConfigured,
  onRelease,
  onReview,
  onStatus,
  onError,
}: {
  actor: string;
  onSelect: (id: number | null) => void;
  /** The global factor state (`integrations/status`), gate for the release dialog. */
  mfaConfigured: boolean;
  /** A factor is enrolled: the release goes through the TOTP dialog. */
  onRelease: (request: { id: number; request_ref: string }) => void;
  /** Close always needs the post-incident review note (contract-required). */
  onReview: (request: { id: number; request_ref: string }) => void;
  onStatus: (message: string | null) => void;
  onError: (message: string) => void;
}) {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  // D3: approver-class decisions render disabled with the reason for the
  // operator (who can file but not sign); open/close are operator-class.
  const canApprove = canOperate(ACTION_OPS.breakGlassApprove, whoami);
  const canDeny = canOperate(ACTION_OPS.breakGlassDeny, whoami);

  const [status, setStatus] = useState<(typeof breakGlassStatuses)[number] | undefined>(
    undefined,
  );

  const requests = useBreakGlassList(status);
  const approveBreakGlass = useApproveBreakGlass();
  const denyBreakGlass = useDenyBreakGlass();
  const openBreakGlass = useOpenBreakGlass();

  const fail = (err: unknown) => onError(err instanceof Error ? err.message : String(err));

  /** One signature: POST .../approve with the acting identity verbatim. */
  const approve = (request: BreakGlassRequest) => {
    onStatus(null);
    approveBreakGlass.mutate(
      { actor, requestId: request.id },
      {
        onSuccess: (data) => onStatus(data.message),
        onError: fail,
      },
    );
  };

  /** Turn the pending request down (legacy posts an empty note body). */
  const deny = (request: BreakGlassRequest) => {
    onStatus(null);
    denyBreakGlass.mutate(
      { actor, requestId: request.id },
      {
        onSuccess: (data) => onStatus(data.message),
        onError: fail,
      },
    );
  };

  /** Unseal: dialog when a factor is enrolled, direct POST when none is. */
  const open = (request: BreakGlassRequest) => {
    if (mfaConfigured) {
      onRelease({ id: request.id, request_ref: request.request_ref });
      return;
    }
    onStatus(null);
    openBreakGlass.mutate(
      { actor, requestId: request.id },
      {
        onSuccess: (data) => onStatus(data.message),
        onError: fail,
      },
    );
  };

  const columns = [
    {
      key: 'request',
      header: t('breakGlass.list.colRequest'),
      render: (row: BreakGlassRequest) => (
        <div className="flex flex-col gap-1">
          <span className="font-code-sm text-code-sm font-semibold text-on-surface">
            {row.request_ref}
          </span>
          <Chip tone={severityTone(row.severity)}>{row.severity}</Chip>
        </div>
      ),
    },
    {
      key: 'target',
      header: t('breakGlass.list.colTarget'),
      render: (row: BreakGlassRequest) => (
        <div className="font-code-sm text-code-sm">
          {row.target}
          <div className="text-outline">{row.protocol}</div>
        </div>
      ),
    },
    {
      key: 'requested',
      header: t('breakGlass.list.colRequested'),
      render: (row: BreakGlassRequest) => (
        <div className="font-code-sm text-code-sm">
          {row.requested_by}
          <div className="text-outline">{row.requested_at}</div>
        </div>
      ),
    },
    {
      key: 'approvals',
      header: t('breakGlass.list.colApprovals'),
      render: (row: BreakGlassRequest) => (
        <div className="font-code-sm text-code-sm">
          <span className="font-semibold">{`${row.approvals_signed}/${row.approvals_required}`}</span>
          <div className="text-outline">
            {row.approvals.length > 0
              ? row.approvals.map((approval) => approval.approver).join(', ')
              : t('breakGlass.list.noSignatures')}
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      header: t('breakGlass.list.colStatus'),
      render: (row: BreakGlassRequest) => (
        <Chip tone={statusTone(row.status)}>{row.status}</Chip>
      ),
    },
    {
      key: 'session',
      header: t('breakGlass.list.colSession'),
      render: (row: BreakGlassRequest) => (
        <span className="font-code-sm text-code-sm">
          {row.session_id !== null ? `sess #${row.session_id}` : '—'}
        </span>
      ),
    },
    {
      key: 'actions',
      header: t('breakGlass.list.colActions'),
      render: (row: BreakGlassRequest) => (
        <div className="flex flex-wrap gap-1.5">
          {row.status === 'pending' ? (
            <>
              <Button
                type="button"
                disabled={approveBreakGlass.isPending || !canApprove}
                title={canApprove ? undefined : t('roleReasons.approver')}
                onClick={() => approve(row)}
              >
                {t('breakGlass.list.approve')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={denyBreakGlass.isPending || !canDeny}
                title={canDeny ? undefined : t('roleReasons.approver')}
                onClick={() => deny(row)}
              >
                {t('breakGlass.list.deny')}
              </Button>
            </>
          ) : null}
          {row.status === 'approved' ? (
            <Button
              type="button"
              variant="destructive"
              disabled={openBreakGlass.isPending}
              onClick={() => open(row)}
            >
              {t('breakGlass.list.openUnseal')}
            </Button>
          ) : null}
          {row.status === 'used' ? (
            <Button type="button" onClick={() => onReview(row)}>
              {t('breakGlass.list.closeReview')}
            </Button>
          ) : null}
          <Button type="button" variant="secondary" onClick={() => onSelect(row.id)}>
            {t('breakGlass.list.inspect')}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('breakGlass.list.title')}
        subtitle={t('breakGlass.list.subtitle')}
        actions={
          requests.data
            ? t('breakGlass.list.count', {
                shown: requests.data.requests.length,
                total: requests.data.total,
              })
            : undefined
        }
      />
      <div
        className="flex flex-wrap items-center gap-space-sm"
        role="group"
        aria-label={t('breakGlass.list.filterStatus')}
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
            {value === 'all' ? t('breakGlass.list.filterAll') : value}
          </button>
        ))}
      </div>
      <SectionBody query={requests}>
        {(data) =>
          data.requests.length === 0 ? (
            <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
              {t('breakGlass.list.empty')}
            </p>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-outline-variant/30">
              <DataTable
                columns={columns}
                rows={data.requests}
                rowKey={(row) => String(row.id)}
                caption={t('breakGlass.list.caption')}
              />
            </div>
          )
        }
      </SectionBody>
    </div>
  );
}
