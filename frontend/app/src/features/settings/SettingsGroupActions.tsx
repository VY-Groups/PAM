/**
 * The card-footer actions (screen 11, ADR-0015):
 *
 * - SMTP test (11.3) - `POST /api/v1/settings/smtp/test` sends a REAL
 *   message. The pristine rig answers the honest 503 refusal naming what
 *   to set; that server line IS the rendered feedback. Success shows the
 *   server's own `message` verbatim.
 * - SCIM rotate (11.3) - `POST /api/v1/settings/scim/rotate` mints a
 *   fresh bearer token, shown exactly once (the response is the only
 *   place it exists; only its sha256 is stored). The rotate breaks the
 *   identity provider's current credential, so it asks first.
 * - ITSM verify (11.4 NEW action - the legacy page has no button for
 *   it, ADR amendment 11.4) - `POST /api/v1/itsm/verify` is a real REST
 *   lookup; the pristine rig refuses with the verbatim 409 BEFORE any
 *   HTTP call and that refusal IS the feedback. (The 200 arm needs a
 *   configured instance - no capture exists on the pristine rigs, so
 *   only its schema-driven `detail` render exists, unasserted - same
 *   note as the SMTP 200 arm.)
 * - LDAP bind (11.4 NEW action, same amendment) - `POST /api/v1/auth/ldap`
 *   runs a real BER BindRequest; the configured check runs first, so the
 *   pristine rig answers the verbatim 409 and no password ever leaves
 *   the request. A 200 can carry a one-time ticket (token mode; uncaptured
 *   on the open rigs) shown exactly once, like the SCIM token above.
 *
 * All four render server errors verbatim (house rule) and the shared
 * "license server unreachable" line for a dead backend.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button } from '../../components';
import { isBackendDown } from '../../api/http';
import { useItsmVerify, useLdapBind, useScimRotate, useSmtpTest } from './queries';

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

export function FeedbackLine({ feedback }: { feedback: ActionFeedback | null }) {
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

/**
 * ITSM ticket verification (11.4 NEW action) - `POST /api/v1/itsm/verify`
 * is a real REST lookup into the instance. The pristine rig refuses with
 * the verbatim 409 `ITSM is not configured` before any HTTP call is made
 * (routes.py:3579-3604) and that refusal IS the feedback. The 200 arm
 * needs a configured instance and is uncapturable on the pristine rigs:
 * only its schema-driven `detail` render exists, unasserted (same note
 * as the SMTP 200 arm).
 */
export function ItsmVerifyAction() {
  const { t } = useTranslation();
  const verify = useItsmVerify();
  const [ticket, setTicket] = useState('');
  const [feedback, setFeedback] = useState<ActionFeedback | null>(null);

  const run = () => {
    setFeedback(null);
    verify.mutate(
      { ticket: ticket.trim() },
      {
        onError: (error) =>
          setFeedback({ tone: 'error', text: actionErrorMessage(error, t) }),
        // `detail` is required in the contract - the server's own verdict
        // string, rendered verbatim; honest error tone when not verified.
        onSuccess: (data) =>
          setFeedback({ tone: data.verified ? 'ok' : 'error', text: data.detail }),
      },
    );
  };

  return (
    <div className="flex flex-col gap-space-sm pt-space-sm border-t border-outline-variant/30">
      <label className="flex flex-col gap-1 font-body-sm text-body-sm text-on-surface-variant">
        {t('settings.forms.actions.itsmTicketLabel')}
        <input
          className={INPUT_CLASS}
          onChange={(event) => setTicket(event.target.value)}
          placeholder={t('settings.forms.actions.itsmTicketHint')}
          type="text"
          value={ticket}
        />
      </label>
      <Button
        data-testid="settings-itsm-verify"
        disabled={verify.isPending}
        icon="task_alt"
        onClick={run}
        variant="secondary"
      >
        {t('settings.forms.actions.itsmVerifyButton')}
      </Button>
      <FeedbackLine feedback={feedback} />
    </div>
  );
}

/**
 * LDAP bind test (11.4 NEW action) - `POST /api/v1/auth/ldap` sends a real
 * BER BindRequest. The pristine rig refuses with the verbatim 409
 * `LDAP is not configured` (configured check runs before auth, service.py:
 * 1879) and no password leaves the request. A 200 is two-honest-arms:
 * token mode carries a one-time `vypam-ldap1...` ticket (shown exactly
 * once like the SCIM token above), open dev mode carries the honest
 * `note` statement instead. Neither 200 arm is capturable on the pristine
 * rigs (always unconfigured); the render is contract-driven, unasserted.
 * No client-side validation: the server's 400 (`'password' is required`,
 * captured) is the honest arm for missing credentials.
 */
export function LdapBindAction() {
  const { t } = useTranslation();
  const bind = useLdapBind();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [minted, setMinted] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<ActionFeedback | null>(null);

  const run = () => {
    setFeedback(null);
    setMinted(null);
    bind.mutate(
      { password, username: username.trim() },
      {
        onError: (error) =>
          setFeedback({ tone: 'error', text: actionErrorMessage(error, t) }),
        onSuccess: (data) => {
          setFeedback({ tone: 'ok', text: data.note ?? '' });
          setMinted(data.ticket);
          setPassword('');
        },
      },
    );
  };

  return (
    <div className="flex flex-col gap-space-sm pt-space-sm border-t border-outline-variant/30">
      <label className="flex flex-col gap-1 font-body-sm text-body-sm text-on-surface-variant">
        {t('settings.forms.actions.ldapUsernameLabel')}
        <input
          className={INPUT_CLASS}
          onChange={(event) => setUsername(event.target.value)}
          placeholder={t('settings.forms.actions.ldapUsernameHint')}
          type="text"
          value={username}
        />
      </label>
      <label className="flex flex-col gap-1 font-body-sm text-body-sm text-on-surface-variant">
        {t('settings.forms.actions.ldapPasswordLabel')}
        <input
          className={INPUT_CLASS}
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          value={password}
        />
      </label>
      <Button
        data-testid="settings-ldap-bind"
        disabled={bind.isPending}
        icon="key"
        onClick={run}
        variant="secondary"
      >
        {t('settings.forms.actions.ldapBindButton')}
      </Button>
      {/* The one-time ticket box: not in the DOM until a 200 actually answered. */}
      {minted ? (
        <div
          className="rounded-lg bg-primary/5 border border-primary/30 p-space-sm"
          data-testid="settings-ldap-ticket-once"
        >
          <span className="font-label-badge text-label-badge text-primary">
            {t('settings.forms.actions.ldapTicketTitle')}
          </span>
          <code className="block mt-1 px-3 py-2 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface break-all">
            {minted}
          </code>
        </div>
      ) : null}
      <FeedbackLine feedback={feedback} />
    </div>
  );
}
