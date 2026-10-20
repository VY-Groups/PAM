import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';
import { Button, NotConnected, StatusDot, Value } from '../../components';
import { useSessionEvents, useSessionList } from '../../features/sessions/queries';

// shortcut: no PTY/websocket/exec operation exists in apis/openapi.yaml
// (ADR-0020 Decision 2), so an interactive terminal is deferred until the
// contract offers one - this drawer is the live session / recording
// inspector (list + recorded events) until then.

/**
 * Console drawer (ADR-0020 Decision 2): toggled from the TopBar, mounted
 * only while open (the 15s session poll runs only then). Lists live
 * sessions from `GET /api/v1/sessions` and shows the selected session's
 * recording from `GET /api/v1/sessions/{id}/events`, with the same
 * honest states as the sessions screen (loading, verbatim error,
 * "not connected" chip, honest empty).
 */
export function ConsoleDrawer({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const list = useSessionList();
  const events = useSessionEvents(selectedId);

  return (
    <aside
      id="console-drawer"
      aria-label={t('shell.drawer.title')}
      className="fixed right-0 top-16 bottom-0 w-96 bg-surface-container-lowest border-l border-outline-variant/30 z-40 flex flex-col shadow-[-2px_0_8px_rgba(0,0,0,0.04)]"
    >
      <div className="h-14 px-space-md flex items-center justify-between border-b border-outline-variant/20">
        <span className="font-label-md text-label-md text-on-surface">
          {t('shell.drawer.title')}
        </span>
        <Button
          variant="secondary"
          icon="close"
          ariaLabel={t('shell.drawer.close')}
          onClick={onClose}
        />
      </div>
      <div className="flex-1 overflow-y-auto p-space-md flex flex-col gap-space-md">
        <div className="flex flex-col gap-1">
          {list.isPending ? (
            <p className="font-body-sm text-body-sm text-outline">
              {t('shell.drawer.loading')}
            </p>
          ) : list.isError ? (
            list.error !== null && list.error !== undefined ? (
              isBackendDown(list.error) ? (
                <NotConnected />
              ) : (
                <p role="alert" className="font-body-sm text-body-sm text-error">
                  {t('shell.drawer.error', {
                    message:
                      list.error instanceof Error ? list.error.message : String(list.error),
                  })}
                </p>
              )
            ) : null
          ) : list.data !== undefined && list.data.items.length === 0 ? (
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('shell.drawer.noSessions')}
            </p>
          ) : list.data !== undefined ? (
            list.data.items.map((session) => (
              <button
                key={session.id}
                type="button"
                aria-pressed={selectedId === session.id}
                onClick={() => setSelectedId(session.id)}
                className={`flex items-center gap-space-sm px-space-sm py-space-sm rounded-lg text-left font-body-sm text-body-sm transition-colors ${
                  selectedId === session.id
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container hover:text-on-surface'
                }`}
              >
                <StatusDot state={session.ended_at ? 'muted' : 'live'} />
                <span className="font-code-sm text-code-sm">{session.session_ref}</span>
                <span className="truncate">{session.target}</span>
              </button>
            ))
          ) : null}
        </div>
        <div className="flex flex-col gap-space-xs border-t border-outline-variant/20 pt-space-md">
          {selectedId === null ? (
            <p className="font-body-sm text-body-sm text-outline">
              {t('shell.drawer.selectPrompt')}
            </p>
          ) : events.isPending ? (
            <p className="font-body-sm text-body-sm text-outline">
              {t('shell.drawer.loading')}
            </p>
          ) : events.isError ? (
            events.error !== null && events.error !== undefined ? (
              isBackendDown(events.error) ? (
                <NotConnected />
              ) : (
                <p role="alert" className="font-body-sm text-body-sm text-error">
                  {t('shell.drawer.error', {
                    message:
                      events.error instanceof Error
                        ? events.error.message
                        : String(events.error),
                  })}
                </p>
              )
            ) : null
          ) : events.data !== undefined && events.data.events.length === 0 ? (
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {t('shell.drawer.noEvents')}
            </p>
          ) : events.data !== undefined ? (
            events.data.events.map((event) => (
              <div
                key={event.id}
                className="flex items-baseline gap-space-sm font-code-sm text-code-sm text-on-surface"
              >
                <span className="text-outline shrink-0">#{event.seq}</span>
                {event.content !== null ? (
                  <span className="truncate">{event.content}</span>
                ) : event.withheld ? (
                  <span className="text-outline italic">{t('shell.drawer.withheld')}</span>
                ) : (
                  <Value />
                )}
              </div>
            ))
          ) : null}
        </div>
      </div>
    </aside>
  );
}
