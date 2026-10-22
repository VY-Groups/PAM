import { useTranslation } from 'react-i18next';
import type { ReactNode } from 'react';
import type { UseQueryResult } from '@tanstack/react-query';

import { isBackendDown } from '../../api/http';
import { BackendDownNotice } from '../../app/error/BackendDownNotice';
import { useAuth } from '../../app/providers/useAuth';
import {
  Button,
  Chip,
  DataTable,
  NotConnected,
  SectionHeader,
  Value,
} from '../../components';
import type { DataTableColumn } from '../../components';
import type {
  BreakGlassRequest,
  BrokerCredential,
  JitRequest,
  VendorAccount,
} from '../../api/generated/models';
import { formatTime } from '../../lib/format';
import {
  useApproveBreakGlassRequest,
  useApproveBrokerCredential,
  useApproveJitRequest,
  useApproveVendorInvite,
  useBrokerCredentialQueue,
  useDenyBreakGlassRequest,
  useDenyBrokerCredential,
  useDenyJitRequest,
  useDenyVendorInvite,
  useInvitedVendors,
  usePendingBreakGlass,
  usePendingJit,
} from './queries';

/**
 * ADR-0021 12.RC - the approver's landing page: one inbox over the four
 * decision surfaces the brief names (JIT, break-glass, vendor, brokered
 * credentials) with requester/ticket/risk context. Counts and rows come
 * from the API or show the honest em-dash; every refusal renders the
 * server's message verbatim (the quorum, the missing vendor step and the
 * role 403 are all server truth). Actions carry the signed-in principal
 * as `X-Actor`. Success feedback is the row leaving the list - server
 * truth via shared-key invalidation, never an optimistic guess.
 */
export function ApprovalsPage() {
  const { t } = useTranslation();
  const { whoami } = useAuth();

  const jit = usePendingJit();
  const breakGlass = usePendingBreakGlass();
  const vendors = useInvitedVendors();
  const broker = useBrokerCredentialQueue();

  const approveJit = useApproveJitRequest();
  const denyJit = useDenyJitRequest();
  const approveBg = useApproveBreakGlassRequest();
  const denyBg = useDenyBreakGlassRequest();
  const approveVendor = useApproveVendorInvite();
  const denyVendor = useDenyVendorInvite();
  const approveBroker = useApproveBrokerCredential();
  const denyBroker = useDenyBrokerCredential();

  const actor = whoami?.principal ?? 'console';

  const backendDownError = [jit.error, breakGlass.error, vendors.error, broker.error].find(
    (error): error is Error => error !== null && isBackendDown(error),
  );

  // One alert channel for decisions: the server's own message, verbatim.
  const mutations = [
    approveJit,
    denyJit,
    approveBg,
    denyBg,
    approveVendor,
    denyVendor,
    approveBroker,
    denyBroker,
  ];
  const busy = mutations.some((mutation) => mutation.isPending);
  const currentError = mutations.find((mutation) => mutation.isError)?.error ?? null;
  const message =
    currentError === null
      ? null
      : currentError instanceof Error
        ? currentError.message
        : String(currentError);

  const jitColumns: DataTableColumn<JitRequest>[] = [
    {
      key: 'id',
      header: t('approvals.cols.id'),
      render: (row) => <Chip>#{row.id}</Chip>,
    },
    {
      key: 'requester',
      header: t('approvals.cols.requester'),
      render: (row) => <span className="font-body-sm text-body-sm">{row.requester}</span>,
    },
    {
      key: 'risk',
      header: t('approvals.cols.risk'),
      render: (row) => <Chip>{`${row.risk.level} · ${row.risk.score}`}</Chip>,
    },
    {
      key: 'ticket',
      header: t('approvals.cols.ticket'),
      render: (row) => <Value value={row.ticket !== '' ? row.ticket : null} />,
    },
    {
      key: 'when',
      header: t('approvals.cols.when'),
      render: (row) => <Value value={formatTime(row.created_at)} />,
    },
    {
      key: 'actions',
      header: t('approvals.cols.actions'),
      render: (row) => {
        // Two-tier rule: offer whichever signature the request still lacks.
        const role = row.approvals.manager == null ? 'manager' : 'security';
        const name = `#${row.id} ${row.requester}`;
        return (
          <div className="flex items-center gap-space-sm">
            <Button
              variant="primary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action:
                  role === 'manager'
                    ? t('approvals.approveManager')
                    : t('approvals.approveSecurity'),
                name,
              })}
              onClick={() => approveJit.mutate({ actor, requestId: row.id, role })}
            >
              {role === 'manager'
                ? t('approvals.approveManager')
                : t('approvals.approveSecurity')}
            </Button>
            <Button
              variant="secondary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.deny'),
                name,
              })}
              onClick={() => denyJit.mutate({ actor, requestId: row.id })}
            >
              {t('approvals.deny')}
            </Button>
          </div>
        );
      },
    },
  ];

  const breakGlassColumns: DataTableColumn<BreakGlassRequest>[] = [
    {
      key: 'ref',
      header: t('approvals.cols.id'),
      render: (row) => <Chip>{row.request_ref}</Chip>,
    },
    {
      key: 'severity',
      header: t('approvals.cols.severity'),
      render: (row) => <Chip>{row.severity}</Chip>,
    },
    {
      key: 'target',
      header: t('approvals.cols.target'),
      render: (row) => <span className="font-body-sm text-body-sm">{row.target}</span>,
    },
    {
      key: 'requestedBy',
      header: t('approvals.cols.requestedBy'),
      render: (row) => (
        <span className="font-body-sm text-body-sm">{row.requested_by}</span>
      ),
    },
    {
      key: 'signed',
      header: t('approvals.cols.signed'),
      render: (row) => (
        <span className="font-body-sm text-body-sm">
          {`${row.approvals_signed}/${row.approvals_required}`}
        </span>
      ),
    },
    {
      key: 'actions',
      header: t('approvals.cols.actions'),
      render: (row) => {
        const name = `${row.request_ref} ${row.requested_by}`;
        return (
          <div className="flex items-center gap-space-sm">
            <Button
              variant="primary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.approve'),
                name,
              })}
              onClick={() => approveBg.mutate({ actor, requestId: row.id })}
            >
              {t('approvals.approve')}
            </Button>
            <Button
              variant="secondary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.deny'),
                name,
              })}
              onClick={() => denyBg.mutate({ actor, requestId: row.id })}
            >
              {t('approvals.deny')}
            </Button>
          </div>
        );
      },
    },
  ];

  const vendorColumns: DataTableColumn<VendorAccount>[] = [
    {
      key: 'id',
      header: t('approvals.cols.id'),
      render: (row) => <Chip>#{row.id}</Chip>,
    },
    {
      key: 'name',
      header: t('approvals.cols.name'),
      render: (row) => <span className="font-body-sm text-body-sm">{row.name}</span>,
    },
    {
      key: 'contact',
      header: t('approvals.cols.contact'),
      render: (row) => <Value value={row.contact ?? null} />,
    },
    {
      key: 'ticket',
      header: t('approvals.cols.ticket'),
      render: (row) => <Value value={row.ticket ?? null} />,
    },
    {
      key: 'when',
      header: t('approvals.cols.when'),
      render: (row) => <Value value={row.created_at ? formatTime(row.created_at) : null} />,
    },
    {
      key: 'actions',
      header: t('approvals.cols.actions'),
      render: (row) => {
        const name = `${row.name} #${row.id}`;
        return (
          <div className="flex items-center gap-space-sm">
            <Button
              variant="primary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.approve'),
                name,
              })}
              onClick={() => approveVendor.mutate({ actor, vendorId: row.id })}
            >
              {t('approvals.approve')}
            </Button>
            <Button
              variant="secondary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.deny'),
                name,
              })}
              onClick={() => denyVendor.mutate({ actor, vendorId: row.id })}
            >
              {t('approvals.deny')}
            </Button>
          </div>
        );
      },
    },
  ];

  const brokerColumns: DataTableColumn<BrokerCredential>[] = [
    {
      key: 'id',
      header: t('approvals.cols.id'),
      render: (row) => <Chip>#{row.id}</Chip>,
    },
    {
      key: 'policy',
      header: t('approvals.cols.policy'),
      render: (row) => <Chip>#{row.policy_id}</Chip>,
    },
    {
      key: 'reason',
      header: t('approvals.cols.reason'),
      render: (row) => <span className="font-body-sm text-body-sm">{row.reason}</span>,
    },
    {
      key: 'ticket',
      header: t('approvals.cols.ticket'),
      render: (row) => <Value value={row.ticket !== '' ? row.ticket : null} />,
    },
    {
      key: 'when',
      header: t('approvals.cols.when'),
      render: (row) => <Value value={formatTime(row.created_at)} />,
    },
    {
      key: 'actions',
      header: t('approvals.cols.actions'),
      render: (row) => {
        const name = `#${row.id} ${row.reason}`;
        return (
          <div className="flex items-center gap-space-sm">
            <Button
              variant="primary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.approve'),
                name,
              })}
              onClick={() => approveBroker.mutate({ actor, credentialId: row.id })}
            >
              {t('approvals.approve')}
            </Button>
            <Button
              variant="secondary"
              disabled={busy}
              ariaLabel={t('approvals.named', {
                action: t('approvals.deny'),
                name,
              })}
              onClick={() => denyBroker.mutate({ actor, credentialId: row.id })}
            >
              {t('approvals.deny')}
            </Button>
          </div>
        );
      },
    },
  ];

  const pendingBrokerRows = (broker.data?.credentials ?? []).filter(
    (row) => row.status === 'pending',
  );

  return (
    <div className="flex w-full flex-col gap-space-xl pt-space-xl">
      <section className="flex flex-col gap-space-sm">
        <Chip>{t('approvals.kicker')}</Chip>
        <h1 className="font-headline-lg text-headline-lg text-on-surface">
          {t('approvals.title')}
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          {t('approvals.subtitle')}
        </p>
      </section>

      {backendDownError !== undefined ? (
        <BackendDownNotice body={t('errors.backendDown')} error={backendDownError} />
      ) : null}

      {message !== null ? (
        <p role="alert" className="font-body-sm text-body-sm text-error">
          {message}
        </p>
      ) : null}

      <section className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('approvals.jitQueue')}
          subtitle={
            jit.data !== undefined ? t('approvals.count', { count: jit.data.total }) : '—'
          }
        />
        <SectionState query={jit}>
          {(data) => (
            <DataTable
              columns={jitColumns}
              rows={data.items}
              rowKey={(row) => String(row.id)}
              caption={t('approvals.jitQueue')}
              emptyMessage={t('approvals.empty')}
            />
          )}
        </SectionState>
      </section>

      <section className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('approvals.breakGlassQueue')}
          subtitle={
            breakGlass.data !== undefined
              ? t('approvals.count', { count: breakGlass.data.total })
              : '—'
          }
        />
        <SectionState query={breakGlass}>
          {(data) => (
            <DataTable
              columns={breakGlassColumns}
              rows={data.requests}
              rowKey={(row) => String(row.id)}
              caption={t('approvals.breakGlassQueue')}
              emptyMessage={t('approvals.empty')}
            />
          )}
        </SectionState>
      </section>

      <section className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('approvals.vendorQueue')}
          subtitle={
            vendors.data !== undefined
              ? t('approvals.count', { count: vendors.data.total })
              : '—'
          }
        />
        <SectionState query={vendors}>
          {(data) => (
            <DataTable
              columns={vendorColumns}
              rows={data.vendors}
              rowKey={(row) => String(row.id)}
              caption={t('approvals.vendorQueue')}
              emptyMessage={t('approvals.empty')}
            />
          )}
        </SectionState>
      </section>

      <section className="flex flex-col gap-space-md">
        <SectionHeader
          title={t('approvals.brokerQueue')}
          subtitle={
            broker.data !== undefined
              ? t('approvals.count', { count: pendingBrokerRows.length })
              : '—'
          }
        />
        <SectionState query={broker}>
          {() => (
            <DataTable
              columns={brokerColumns}
              rows={pendingBrokerRows}
              rowKey={(row) => String(row.id)}
              caption={t('approvals.brokerQueue')}
              emptyMessage={t('approvals.empty')}
            />
          )}
        </SectionState>
      </section>
    </div>
  );
}

/**
 * Feature-local honest state machine (the JIT screen's SectionBody
 * precedent, plan §3 rule 2 - features never import each other): loading
 * line, transport chip, verbatim section error, real content when the
 * contract answers.
 */
function SectionState<T>({
  query,
  children,
}: {
  query: UseQueryResult<T>;
  children: (data: T) => ReactNode;
}) {
  const { t } = useTranslation();
  if (query.isPending) {
    return (
      <p className="p-space-md font-body-sm text-body-sm text-outline">
        {t('approvals.loading')}
      </p>
    );
  }
  if (query.error !== null && query.error !== undefined) {
    if (isBackendDown(query.error)) return <NotConnected />;
    const message =
      query.error instanceof Error ? query.error.message : String(query.error);
    return (
      <p role="alert" className="p-space-md font-body-sm text-body-sm text-error">
        {t('approvals.sectionError', { message })}
      </p>
    );
  }
  if (query.data === undefined) return null;
  return <>{children(query.data)}</>;
}
