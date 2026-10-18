import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import { Chip, SectionHeader, StatusDot } from '../../components';
import { useHsmStatus } from './queries';

/**
 * Hardware Security Module (HSM) & KMS custody posture (screen 11,
 * ADR-0015). The live line mirrors the legacy `platform_settings_center`
 * wording: `sealed/unsealed · mode · provider | no provider configured -
 * advisory file custody`, with the seal chip and the key-in-use chip.
 *
 * A sealed vault is NOT dressed up as healthy: the seal chip reads
 * `sealed` in the error tone and the line says so verbatim. A dead
 * backend renders the honest "not connected" rail rather than an
 * "unsealed" claim, which would be false.
 *
 * 11.3: the trailing `children` slot hosts the `hsm` settings form
 * (Stored Configuration block) inside this posture section, exactly
 * where the legacy page renders it.
 */
export function HsmStatusSection({ children }: { children?: ReactNode }) {
  const { t } = useTranslation();
  const hsm = useHsmStatus();
  const data = hsm.isError ? undefined : hsm.data;

  return (
    <section className="flex flex-col gap-space-md" data-testid="settings-hsm">
      <SectionHeader
        subtitle={t('settings.hsm.subtitle')}
        title={t('settings.hsm.title')}
      />

      <p
        className="font-body-sm text-body-sm text-on-surface-variant"
        data-testid="settings-hsm-line"
      >
        {hsm.isError
          ? t('settings.hsm.unreachable')
          : !data
            ? '\u2014'
            : data.provider === ''
              ? t('settings.hsm.lineNoProvider')
              : data.sealed
                ? t('settings.hsm.lineSealed', {
                    probe: t(
                      data.last_health?.reachable
                        ? 'settings.hsm.probeReachable'
                        : 'settings.hsm.probeNever',
                    ),
                    provider: data.provider,
                    reason: data.seal_reason,
                    rotation: t(data.rotation_due ? 'settings.on' : 'settings.off'),
                  })
                : t('settings.hsm.lineUnsealed', {
                    probe: t(
                      data.last_health?.reachable
                        ? 'settings.hsm.probeReachable'
                        : 'settings.hsm.probeNever',
                    ),
                    provider: data.provider,
                    rotation: t(data.rotation_due ? 'settings.on' : 'settings.off'),
                  })}
      </p>

      <div
        aria-label={t('settings.hsm.chipsLabel')}
        className="flex flex-wrap items-center gap-space-sm"
        role="group"
      >
        <Chip className="gap-1.5">
          <StatusDot state={data ? (data.sealed ? 'error' : 'ok') : 'muted'} />
          {data ? t(data.sealed ? 'settings.hsm.sealed' : 'settings.hsm.unsealed') : ''}
        </Chip>
        <Chip className="gap-1.5">
          {/* Legacy tone: enforced=ok, advisory=warn. The design system has no
              warn dot, so advisory maps to `muted` - a deliberate, documented
              down-grade, never an "ok" for a mode that does not enforce. */}
          <StatusDot state={data ? (data.mode === 'enforced' ? 'ok' : 'muted') : 'muted'} />
          {data ? t('settings.hsm.mode', { mode: data.mode }) : ''}
        </Chip>
        <Chip className="gap-1.5">
          <StatusDot
            state={data ? (data.key_in_use === 'provider' ? 'ok' : 'muted') : 'muted'}
          />
          {data ? t('settings.hsm.keyInUse', { key: data.key_in_use }) : ''}
        </Chip>
      </div>

      {children}
    </section>
  );
}
