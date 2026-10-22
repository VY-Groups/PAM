import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, Modal, SectionHeader } from '../../components';
import type { CloudConnector } from '../../api/generated/models';
import { ACTION_OPS, canOperate } from '../../app/guards/RoleGate';
import { useAuth } from '../../app/providers/useAuth';
import { formatTime } from '../../lib/format';
import { ConnectorDialog } from './ConnectorDialog';
import { SectionBody } from './SectionBody';
import {
  useCloudConnectors,
  useDiscoverConnector,
  useProbeConnector,
  useRemoveConnector,
} from './queries';
import { connectorProviders, connectorStatuses } from './schemas';

/** The provider chips the contract's filter enum offers, `all` first. */
const PROVIDER_FILTERS = ['all', ...connectorProviders] as const;
/** The status chips the contract's filter enum offers, `all` first. */
const STATUS_FILTERS = ['all', ...connectorStatuses] as const;

/** Per-connector action outcome (probe/discover), rendered verbatim. */
type ActionResult = { message: string; error?: string };

/**
 * Cloud PAM connectors (F4 screen 7, plan §4 line 109 "cloud
 * connectors"). Filter chips drive the contract's own `provider` /
 * `status` parameters; every row action is a real cloud write carrying
 * the signed-in principal in `X-Actor`: Probe runs a live probe
 * (`POST .../test`) whose detail/latency render verbatim, Discover
 * imports inventory (`POST .../discover`) whose counts or refusal
 * message render verbatim (a credential-less connector is refused 409
 * by the server, honestly), and Remove asks for confirmation before
 * `DELETE .../{id}`.
 */
export function ConnectorsSection({ actor }: { actor: string }) {
  const { t } = useTranslation();
  const { whoami } = useAuth();
  // D3: create/probe/remove are administrator-class (only admin holds them
  // in ADMIN_OPERATIONS); Discover is operator-class and stays enabled.
  const canCreate = canOperate(ACTION_OPS.connectorCreate, whoami);
  const canProbe = canOperate(ACTION_OPS.connectorTest, whoami);
  const canRemove = canOperate(ACTION_OPS.connectorDelete, whoami);

  const [provider, setProvider] = useState<(typeof PROVIDER_FILTERS)[number] | undefined>(
    undefined,
  );
  const [status, setStatus] = useState<(typeof STATUS_FILTERS)[number] | undefined>(
    undefined,
  );

  const connectors = useCloudConnectors({
    ...(provider && provider !== 'all' ? { provider } : {}),
    ...(status && status !== 'all' ? { status } : {}),
  });
  const probe = useProbeConnector();
  const discover = useDiscoverConnector();
  const remove = useRemoveConnector();

  const [addOpen, setAddOpen] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<CloudConnector | null>(null);
  const [rowStatus, setRowStatus] = useState<Record<number, ActionResult>>({});
  const [sectionStatus, setSectionStatus] = useState<string | null>(null);

  /** Probe / discover outcomes land next to their own connector row. */
  const note = (id: number, message: string, error?: string) => {
    setRowStatus((prev) => ({
      ...prev,
      [id]: error === undefined ? { message } : { message, error },
    }));
  };

  const onProbe = (connector: CloudConnector) => {
    probe.mutate(
      { actor, connectorId: connector.id },
      {
        onSuccess: (data) => note(connector.id, data.message),
        onError: (err) =>
          note(connector.id, '', err instanceof Error ? err.message : String(err)),
      },
    );
  };

  const onDiscover = (connector: CloudConnector) => {
    discover.mutate(
      { actor, connectorId: connector.id },
      {
        onSuccess: (data) =>
          note(
            connector.id,
            `${data.message} — ${t('infrastructure.connectors.discoveredCounts', {
              added: data.new,
              updated: data.updated,
            })}`,
          ),
        onError: (err) =>
          note(connector.id, '', err instanceof Error ? err.message : String(err)),
      },
    );
  };

  const onRemove = () => {
    if (removeTarget === null) return;
    const target = removeTarget;
    setSectionStatus(null);
    remove.mutate(
      { actor, connectorId: target.id },
      {
        onSuccess: (data) => {
          setRemoveTarget(null);
          setSectionStatus(data.message ?? t('infrastructure.states.actionDone'));
        },
        onError: (err) =>
          note(target.id, '', err instanceof Error ? err.message : String(err)),
      },
    );
  };

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('infrastructure.connectors.title')}
        subtitle={t('infrastructure.connectors.subtitle')}
        actions={
          <>
            {connectors.data
              ? t('infrastructure.connectors.count', {
                  shown: connectors.data.connectors.length,
                  total: connectors.data.total,
                })
              : undefined}
            <Button
              type="button"
              icon="add_circle"
              disabled={!canCreate}
              title={canCreate ? undefined : t('roleReasons.administrator')}
              onClick={() => setAddOpen(true)}
            >
              {t('infrastructure.actions.addConnector')}
            </Button>
          </>
        }
      />
      <div className="flex flex-wrap items-center gap-space-sm">
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('infrastructure.connectors.filterProvider')}
        >
          {PROVIDER_FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={(provider ?? 'all') === value}
              onClick={() => setProvider(value)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                (provider ?? 'all') === value
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {value === 'all' ? t('infrastructure.connectors.filterAllProviders') : value}
            </button>
          ))}
        </div>
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('infrastructure.connectors.filterStatus')}
        >
          {STATUS_FILTERS.map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={(status ?? 'all') === value}
              onClick={() => setStatus(value)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                (status ?? 'all') === value
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {value === 'all' ? t('infrastructure.connectors.filterAnyStatus') : value}
            </button>
          ))}
        </div>
      </div>
      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-code-sm text-code-sm text-tertiary"
      >
        {sectionStatus ?? ''}
      </p>
      <SectionBody query={connectors}>
        {(data) =>
          data.connectors.length === 0 ? (
            <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
              {t('infrastructure.connectors.empty')}
            </p>
          ) : (
            <div className="flex flex-col gap-space-sm">
              {data.connectors.map((connector) => {
                const result = rowStatus[connector.id];
                return (
                  <div
                    key={connector.id}
                    className="flex flex-col gap-space-xs rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm"
                  >
                    <div className="flex flex-wrap items-center gap-space-sm">
                      <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                        {connector.name}
                      </span>
                      <Chip tone="inactive">{connector.provider}</Chip>
                      <Chip tone={connector.status === 'connected' ? 'info' : 'inactive'}>
                        {connector.status}
                      </Chip>
                      <span className="ml-auto flex flex-wrap gap-space-sm">
                        <Button
                          type="button"
                          variant="secondary"
                          disabled={probe.isPending || remove.isPending || !canProbe}
                          title={canProbe ? undefined : t('roleReasons.administrator')}
                          onClick={() => onProbe(connector)}
                        >
                          {t('infrastructure.actions.probe')}
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          disabled={discover.isPending || remove.isPending}
                          onClick={() => onDiscover(connector)}
                        >
                          {t('infrastructure.actions.discover')}
                        </Button>
                        <Button
                          type="button"
                          disabled={!canRemove}
                          title={canRemove ? undefined : t('roleReasons.administrator')}
                          onClick={() => setRemoveTarget(connector)}
                        >
                          {t('infrastructure.actions.remove')}
                        </Button>
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-space-sm font-code-sm text-code-sm text-outline">
                      <span>
                        {`${t('infrastructure.connectors.accountRef')}: ${
                          connector.account_ref || '—'
                        }`}
                      </span>
                      <span>
                        {`${t('infrastructure.connectors.endpoint')}: ${
                          connector.endpoint || '—'
                        }`}
                      </span>
                      <span className="ml-auto">
                        {t('infrastructure.connectors.registeredBy', {
                          who: connector.created_by,
                          at: formatTime(connector.created_at) ?? '—',
                        })}
                      </span>
                    </div>
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {connector.last_test_at
                        ? t('infrastructure.connectors.lastProbe', {
                            detail: connector.last_test_detail || '—',
                            at: formatTime(connector.last_test_at) ?? '—',
                          })
                        : t('infrastructure.connectors.neverProbed')}
                    </span>
                    {result ? (
                      <>
                        <p
                          role="status"
                          className="font-code-sm text-code-sm text-tertiary"
                        >
                          {result.message}
                        </p>
                        {result.error ? (
                          <p role="alert" className="font-body-sm text-body-sm text-error">
                            {result.error}
                          </p>
                        ) : null}
                      </>
                    ) : null}
                  </div>
                );
              })}
            </div>
          )
        }
      </SectionBody>

      <ConnectorDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        actor={actor}
        onStatus={setSectionStatus}
      />
      <Modal
        open={removeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRemoveTarget(null);
        }}
        title={t('infrastructure.dialogs.removeTitle')}
        closeLabel={t('common.close')}
        footer={
          <>
            <Button type="button" variant="secondary" onClick={() => setRemoveTarget(null)}>
              {t('infrastructure.dialogs.cancel')}
            </Button>
            <Button type="button" disabled={remove.isPending} onClick={onRemove}>
              {remove.isPending
                ? t('infrastructure.dialogs.removing')
                : t('infrastructure.dialogs.removeSubmit')}
            </Button>
          </>
        }
      >
        <p className="font-body-sm text-body-sm text-on-surface">
          {t('infrastructure.dialogs.removeBody', {
            name: removeTarget?.name ?? '—',
          })}
        </p>
      </Modal>
    </div>
  );
}
