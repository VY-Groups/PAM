import { useTranslation } from 'react-i18next';

import { Chip, SectionHeader, Value } from '../../components';
import type { SessionGateway, SessionWatermark } from '../../api/generated/models';

/**
 * The section-12 watermark card and the section-27/8a protocol-overlay
 * line (plan §4 line 108 "watermark overlay"). Every fact comes from the
 * detail response: the six watermark fields the server assembled, the
 * rendered payload while the control is on (an honest "nothing is painted"
 * line when it is off), and the gateway half verbatim - connected, an
 * ended/closed gateway session with its closure reason, or an honest "not
 * connected" stating why this session never rode the gateway. The wording
 * matches the legacy hub's line so both screens say the same thing about
 * the same server truth.
 */
export function WatermarkCard({
  watermark,
  gateway,
  loaded,
}: {
  watermark: SessionWatermark | undefined;
  gateway: SessionGateway;
  loaded: boolean;
}) {
  const { t } = useTranslation();
  const fields = watermark?.fields;

  return (
    <section
      className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-md shadow-sm"
      aria-label={t('sessions.watermark.heading')}
    >
      <SectionHeader
        title={t('sessions.watermark.heading')}
        actions={
          watermark ? (
            <Chip tone={watermark.state === 'active' ? 'info' : 'inactive'}>
              {watermark.state}
            </Chip>
          ) : null
        }
      />
      <dl className="grid grid-cols-2 gap-space-sm">
        <WatermarkField label={t('sessions.watermark.user')} value={fields?.user} />
        <WatermarkField label={t('sessions.watermark.session')} value={fields?.session} />
        <WatermarkField label={t('sessions.watermark.target')} value={fields?.target} />
        <WatermarkField label={t('sessions.watermark.time')} value={fields?.time} />
        <WatermarkField label={t('sessions.watermark.ticket')} value={fields?.ticket} />
        <WatermarkField label={t('sessions.watermark.source')} value={fields?.source} />
      </dl>
      <pre className="whitespace-pre-wrap break-all rounded-lg bg-surface-container-low p-space-sm font-code-sm text-code-sm text-on-surface-variant">
        {watermark && watermark.enabled && watermark.text
          ? watermark.text
          : t('sessions.watermark.off')}
      </pre>
      <p className="font-body-sm text-body-sm text-on-surface-variant">
        {overlayLine(gateway, loaded, t)}
      </p>
    </section>
  );
}

function WatermarkField({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="flex flex-col rounded-lg bg-surface-container-low p-space-sm">
      <dt className="font-label-badge text-label-badge uppercase text-outline">{label}</dt>
      <dd className="m-0 font-body-sm text-body-sm text-on-surface">
        <Value value={value ?? null} />
      </dd>
    </div>
  );
}

type Translate = (key: string, options?: Record<string, unknown>) => string;

/**
 * The protocol-overlay line (legacy `gatewayOverlayLine`, verbatim
 * wording): awaiting load, not brokered, connected through a node with the
 * injection fact the server reports, or an ended gateway session.
 */
function overlayLine(gateway: SessionGateway, loaded: boolean, t: Translate): string {
  if (!loaded) return t('sessions.watermark.overlayAwaiting');
  if (gateway === null || gateway === undefined) {
    return t('sessions.watermark.overlayNone');
  }
  const node = gateway.node
    ? `${gateway.node.name} (${gateway.node.state})`
    : t('sessions.watermark.noNode');
  if (gateway.state === 'active') {
    return t('sessions.watermark.overlayConnected', {
      node,
      injection: gateway.credential_injected
        ? t('sessions.watermark.injected')
        : t('sessions.watermark.notInjected'),
      segments: gateway.recording.segments,
    });
  }
  return t('sessions.watermark.overlayEnded', {
    state: gateway.state,
    endReason: gateway.end_reason ? ` (${gateway.end_reason})` : '',
    node,
  });
}
