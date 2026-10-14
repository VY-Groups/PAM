import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Chip, SectionHeader } from '../../components';
import { formatTime } from '../../lib/format';
import { ScanDialog } from './ScanDialog';
import { SectionBody } from './SectionBody';
import { useDiscoveryScans } from './queries';

/**
 * Automated network discovery (F4 screen 7, plan §4 line 109 "Scans").
 * "Run Discovery Scan" fires a REAL synchronous TCP-connect probe of
 * the operator's scope through `POST /api/v1/discovery/scans` - the
 * dialog cannot invent a default scope, and the scan history renders
 * the rig's own rows: scope, method, status, ports, host/service
 * counters, who triggered it and when it ran, errors included.
 */
export function ScansSection() {
  const { t } = useTranslation();
  const scans = useDiscoveryScans();

  const [scanOpen, setScanOpen] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  return (
    <div className="flex flex-col gap-space-md">
      <SectionHeader
        title={t('infrastructure.scans.title')}
        subtitle={t('infrastructure.scans.subtitle')}
        actions={
          <>
            {scans.data
              ? t('infrastructure.scans.count', {
                  shown: scans.data.scans.length,
                  total: scans.data.total,
                })
              : undefined}
            <Button type="button" icon="radar" onClick={() => setScanOpen(true)}>
              {t('infrastructure.actions.scan')}
            </Button>
          </>
        }
      />
      <p
        role="status"
        aria-live="polite"
        className="min-h-5 font-code-sm text-code-sm text-tertiary"
      >
        {status ?? ''}
      </p>
      <SectionBody query={scans}>
        {(data) =>
          data.scans.length === 0 ? (
            <p className="p-space-md font-body-sm text-body-sm text-on-surface-variant">
              {t('infrastructure.scans.empty')}
            </p>
          ) : (
            <div className="flex flex-col gap-space-sm">
              {data.scans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex flex-col gap-space-xs rounded-lg border border-outline-variant/30 bg-surface-container-lowest px-space-md py-space-sm"
                >
                  <div className="flex flex-wrap items-center gap-space-sm">
                    <span className="font-body-sm text-body-sm font-semibold text-on-surface">
                      {scan.scope}
                    </span>
                    <Chip tone="inactive">{scan.method}</Chip>
                    <Chip tone={scan.status === 'completed' ? 'info' : 'inactive'}>
                      {scan.status}
                    </Chip>
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {scan.ports.length > 0
                        ? scan.ports.map(String).join(', ')
                        : t('infrastructure.scans.defaultPorts')}
                    </span>
                    <span className="ml-auto font-body-sm text-body-sm text-outline">
                      {t('infrastructure.scans.counters', {
                        probed: scan.hosts_probed,
                        open: scan.hosts_open,
                        services: scan.services_found,
                      })}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-space-sm font-code-sm text-code-sm text-outline">
                    <span>
                      {t('infrastructure.scans.triggeredBy', { who: scan.triggered_by })}
                    </span>
                    <span>
                      {formatTime(scan.started_at) ?? '—'}
                      {' → '}
                      {formatTime(scan.finished_at) ?? t('infrastructure.scans.running')}
                    </span>
                  </div>
                  {scan.error ? (
                    <p role="alert" className="font-body-sm text-body-sm text-error">
                      {scan.error}
                    </p>
                  ) : null}
                </div>
              ))}
            </div>
          )
        }
      </SectionBody>
      <ScanDialog open={scanOpen} onOpenChange={setScanOpen} onStatus={setStatus} />
    </div>
  );
}
