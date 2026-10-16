import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button, Modal } from '../../components';
import type { LicenseRecord } from '../../api/generated/models';
import { useLicenseFile } from './queries';

/**
 * Signed-file viewer (F4 screen 10): `GET /api/v1/licenses/{key}/file`
 * in the contract's two wire formats. The json arm answers the envelope
 * as JSON, the jwt arm answers the compact token as raw `text/plain` -
 * both are rendered verbatim (the shared mutator passes non-JSON bodies
 * through), so the operator sees exactly the bytes an air-gapped peer
 * would verify. Not a form (nothing is posted): the format select is
 * plain state, so no RHF/Zod is involved (ADR-0006 covers mutations).
 */
export function FileDialog({
  open,
  onOpenChange,
  license,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  license: LicenseRecord | null;
}) {
  const { t } = useTranslation();
  const [format, setFormat] = useState<'json' | 'jwt'>('json');

  // The format resets on close (an event transition - never setState
  // in an effect): the next open starts at the json envelope again.
  const setOpen = (nextOpen: boolean) => {
    if (!nextOpen) setFormat('json');
    onOpenChange(nextOpen);
  };

  const file = useLicenseFile(license?.license_key ?? null, format, open);

  const rendered =
    typeof file.data === 'string'
      ? file.data
      : file.data !== undefined
        ? JSON.stringify(file.data, null, 2)
        : '';

  return (
    <Modal
      open={open}
      onOpenChange={setOpen}
      title={t('licensing.dialogs.fileTitle', {
        license: license?.license_id ?? license?.license_key ?? '—',
      })}
      closeLabel={t('common.close')}
      footer={
        <Button type="button" variant="secondary" onClick={() => setOpen(false)}>
          {t('licensing.dialogs.close')}
        </Button>
      }
    >
      <div className="flex flex-col gap-space-sm">
        <div
          className="flex flex-wrap items-center gap-space-sm"
          role="group"
          aria-label={t('licensing.dialogs.fileFormat')}
        >
          {(['json', 'jwt'] as const).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={format === value}
              onClick={() => setFormat(value)}
              className={`rounded px-2 py-1 font-label-badge text-label-badge uppercase tracking-wider transition-colors ${
                format === value
                  ? 'bg-surface-container text-primary'
                  : 'text-outline hover:bg-surface-container-high'
              }`}
            >
              {value}
            </button>
          ))}
        </div>
        {file.isPending ? (
          <p className="font-body-sm text-body-sm text-outline">
            {t('licensing.states.loading')}
          </p>
        ) : null}
        {file.isError ? (
          <p role="alert" className="font-body-sm text-body-sm text-error">
            {t('licensing.dialogs.fileError', {
              message:
                file.error instanceof Error ? file.error.message : String(file.error),
            })}
          </p>
        ) : null}
        {rendered !== '' ? (
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-container-low p-2 font-code-sm text-code-sm text-on-surface">
            {rendered}
          </pre>
        ) : null}
        <p className="font-code-sm text-code-sm text-outline">
          {t('licensing.dialogs.fileNote', { format })}
        </p>
      </div>
    </Modal>
  );
}
