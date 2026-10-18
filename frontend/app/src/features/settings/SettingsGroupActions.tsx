/**
 * The two 11.3 actions the legacy page does NOT have (screen 11,
 * ADR-0015: both endpoints exist, no legacy button calls them):
 *
 * - SMTP test - `POST /api/v1/settings/smtp/test` sends a REAL message.
 *   The pristine rig answers the honest 503 refusal naming what to set;
 *   that server line IS the rendered feedback. Success shows the
 *   server's own `message` verbatim.
 * - SCIM rotate - `POST /api/v1/settings/scim/rotate` mints a fresh
 *   bearer token, shown exactly once (the response is the only place it
 *   exists; only its sha256 is stored). The rotate breaks the identity
 *   provider's current credential, so it asks first.
 *
 * Both render server errors verbatim (house rule) and the shared
 * "license server unreachable" line for a dead backend.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button } from '../../components';
import { isBackendDown } from '../../api/http';
import { useScimRotate, useSmtpTest } from './queries';

const INPUT_CLASS =
  'px-3 py-2 rounded bg-surface-container-lowest text-on-surface font-body-sm text-body-sm ' +
  'border border-outline-variant/40 focus:outline-none focus:ring-1 focus:ring-primary-container';

function actionErrorMessage(error: unknown, t: (key: string) => string): string {
  if (isBackendDown(error)) return t('settings.forms.actions.unreachable');
  return error instanceof Error ? error.message : t('settings.forms.actions.unreachable');
}

interface ActionFeedback {
  tone: 'error' | 'ok';
  text: string;
}

function FeedbackLine({ feedback }: { feedback: ActionFeedback | null }) {
  if (!feedback || !feedback.text) return null;
  return (
    <p
      aria-live="polite"
      className={
        feedback.tone === 'error'
          ? 'font-body-sm text-body-sm text-error'
          : 'font-body-sm text-body-sm text-on-surface-variant'
      }
      role={feedback.tone === 'error' ? 'alert' : 'status'}
    >
      {feedback.text}
    </p>
  );
}

/** The SMTP test affordance, rendered in the smtp card's footer slot. */
export function SmtpTestAction() {
  const { t } = useTranslation();
  const smtpTest = useSmtpTest();
  const [to, setTo] = useState('');
  const [feedback, setFeedback] = useState<ActionFeedback | null>(null);

  const send = () => {
    setFeedback(null);
    smtpTest.mutate(to.trim(), {
      onError: (error) =>
        setFeedback({ tone: 'error', text: actionErrorMessage(error, t) }),
      // The server's own `message` ("Test message sent") verbatim; on an
      // unconfigured rig the 503 above is what renders. (The 200 schema is
      // an untyped map - only a string is rendered, never a coerced one.)
      onSuccess: (data) =>
        setFeedback({
          tone: 'ok',
          text: typeof data.message === 'string' ? data.message : '',
        }),
    });
  };

  return (
    <div className="flex flex-col gap-space-sm pt-space-sm border-t border-outline-variant/30">
      <label className="flex flex-col gap-1 font-label-md text-label-md text-on-surface">
        {t('settings.forms.actions.smtpTestRecipient')}
        <input
          className={INPUT_CLASS}
          onChange={(event) => setTo(event.target.value)}
          placeholder={t('settings.forms.actions.smtpTestRecipientHint')}
          type="email"
          value={to}
        />
      </label>
      <Button disabled={smtpTest.isPending} icon="send" onClick={send} variant="secondary">
        {t('settings.forms.actions.smtpTestButton')}
      </Button>
      <FeedbackLine feedback={feedback} />
    </div>
  );
}

/** The SCIM token rotation affordance, rendered in the scim card slot. */
export function ScimRotateAction() {
  const { t } = useTranslation();
  const rotate = useScimRotate();
  const [minted, setMinted] = useState<{ token: string; message: string } | null>(null);
  const [feedback, setFeedback] = useState<ActionFeedback | null>(null);

  const onRotate = () => {
    if (!window.confirm(t('settings.forms.actions.scimRotateConfirm'))) return;
    setFeedback(null);
    setMinted(null);
    rotate.mutate(undefined, {
      onError: (error) =>
        setFeedback({ tone: 'error', text: actionErrorMessage(error, t) }),
      onSuccess: (data) =>
        setMinted({ token: data.token ?? '', message: data.message ?? '' }),
    });
  };

  return (
    <div className="flex flex-col gap-space-sm pt-space-sm border-t border-outline-variant/30">
      <Button
        disabled={rotate.isPending}
        icon="autorenew"
        onClick={onRotate}
        variant="secondary"
      >
        {t('settings.forms.actions.scimRotateButton')}
      </Button>
      {/*
        The one-time token box: not in the DOM until the rotation actually
        answered - the token exists exactly once, in this response.
      */}
      {minted ? (
        <div
          className="rounded-lg bg-primary/5 border border-primary/30 p-space-sm"
          data-testid="settings-scim-token-once"
        >
          <span className="font-label-badge text-label-badge text-primary">
            {t('settings.forms.actions.scimTokenTitle')}
          </span>
          <code className="block mt-1 px-3 py-2 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface break-all">
            {minted.token}
          </code>
          {minted.message ? (
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              {minted.message}
            </p>
          ) : null}
        </div>
      ) : null}
      <FeedbackLine feedback={feedback} />
    </div>
  );
}
