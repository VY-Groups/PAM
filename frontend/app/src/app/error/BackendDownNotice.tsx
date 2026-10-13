import { useTranslation } from 'react-i18next';

import { isBackendDown } from '../../api/http';

export interface BackendDownNoticeProps {
  /** Body text (i18n) - callers name the context ("data unavailable", …). */
  body: string;
  /** Optional heading (i18n); defaults to none. */
  title?: string;
  /** The transport failure, when present - renders the honest detail line. */
  error?: unknown;
}

/**
 * The shared backend-down state (plan §5): one banner, same wording,
 * everywhere. `role="alert"` announces it; the detail line carries the
 * real reason (network vs timeout) and message from the wrapper.
 */
export function BackendDownNotice({ body, title, error }: BackendDownNoticeProps) {
  const { t } = useTranslation();
  const detail =
    error !== undefined && isBackendDown(error)
      ? t('errors.backendDownDetail', { reason: error.reason, message: error.message })
      : undefined;

  return (
    <div
      role="alert"
      className="mb-space-lg flex items-start gap-space-sm rounded-xl border border-error bg-error-container px-space-lg py-space-md text-on-error-container"
    >
      <span className="material-symbols-outlined text-[20px]" aria-hidden="true">
        warning
      </span>
      <div className="flex flex-col gap-1">
        {title ? (
          <p className="font-label-md text-label-md font-semibold">{title}</p>
        ) : null}
        <p className="font-body-sm text-body-sm">{body}</p>
        {detail ? <p className="font-code-sm text-code-sm">{detail}</p> : null}
      </div>
    </div>
  );
}
