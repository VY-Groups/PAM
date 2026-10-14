import { useTranslation } from 'react-i18next';

import { SectionHeader } from '../../components';
import type { Session, SessionEvent } from '../../api/generated/models';

/**
 * The recording's event stream (plan §4 line 108 "event stream"): every
 * recorded row rendered from contract data only - command lines carry the
 * real prompt, blocked actions are kept as evidence rows (never hidden),
 * withheld keystrokes say so, and each row shows its custody watermark
 * when the server recorded one. The legacy hub rendered the same facts
 * twice (terminal mirror + timeline); this screen reports them once with
 * both badges, so the information is identical and the surface is not
 * duplicated.
 */
export function EventStream({
  session,
  events,
  eventCount,
  blockedCount,
}: {
  session: Session;
  events: SessionEvent[];
  eventCount: number;
  blockedCount: number;
}) {
  const { t } = useTranslation();
  const host = session.target.split(':')[0];
  const withheld = events.filter((event) => event.withheld).length;

  return (
    <section
      className="flex flex-col gap-space-sm rounded-xl bg-surface-container-lowest p-space-md shadow-sm"
      aria-label={t('sessions.stream.heading')}
    >
      <SectionHeader
        title={t('sessions.stream.heading')}
        subtitle={t('sessions.stream.summary', {
          count: eventCount,
          blocked: blockedCount,
          withheld,
        })}
      />
      {events.length === 0 ? (
        <p className="font-body-sm text-body-sm text-on-surface-variant">
          {t('sessions.stream.empty', { ref: session.session_ref })}
        </p>
      ) : (
        <ol className="flex flex-col gap-space-xs">
          {events.map((event) => (
            <li key={event.seq} className="flex flex-col gap-0.5">
              <StreamRow event={event} host={host} actor={session.actor} />
              {event.watermark ? (
                <span className="break-all font-code-sm text-code-sm text-outline">
                  {t('sessions.stream.custody', { watermark: event.watermark })}
                </span>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** One recorded row in its honest shape (blocked rows stay visible). */
function StreamRow({
  event,
  host,
  actor,
}: {
  event: SessionEvent;
  host: string;
  actor: string;
}) {
  const { t } = useTranslation();
  const time = event.created_at.slice(11, 19);

  if (!event.allowed) {
    return (
      <div className="flex items-start gap-space-sm rounded-lg bg-error-container/30 p-space-sm">
        <span className="font-code-sm text-code-sm font-semibold text-error">{time}</span>
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="font-code-sm text-code-sm text-error">
            {t('sessions.stream.blocked', {
              type: event.type,
              reason: event.blocked_reason ?? 'control',
            })}
          </span>
          <span className="font-body-sm text-body-sm text-error">
            {t('sessions.stream.blockedSub')}
          </span>
        </div>
        <span className="rounded bg-error px-1.5 py-0.5 font-code-sm text-[10px] font-bold text-on-error">
          {t('sessions.stream.blockedBadge')}
        </span>
      </div>
    );
  }

  if (event.type === 'command') {
    return (
      <div className="rounded-lg bg-surface-container-low p-space-sm">
        <code className="font-code-sm text-code-sm font-bold text-tertiary-fixed-dim">
          {`${actor}@${host}:~$`}
        </code>
        <span className="ml-space-sm font-code-sm text-code-sm text-on-surface">
          {event.content ?? ''}
        </span>
      </div>
    );
  }

  if (event.withheld) {
    return (
      <div className="rounded-lg bg-surface-container-low p-space-sm font-code-sm text-code-sm text-outline">
        {t('sessions.stream.withheld', { time })}
      </div>
    );
  }

  if (event.type === 'keystroke') {
    return (
      <div className="rounded-lg bg-surface-container-low p-space-sm font-code-sm text-code-sm text-secondary-fixed">
        {t('sessions.stream.keystroke', { time, content: event.content ?? '' })}
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-container-low p-space-sm font-code-sm text-code-sm text-on-surface-variant">
      {t('sessions.stream.row', {
        time,
        type: event.type,
        content: event.content ?? `(${event.type})`,
      })}
    </div>
  );
}
