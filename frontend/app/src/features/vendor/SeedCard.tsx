import { useTranslation } from 'react-i18next';

import { Button, Chip } from '../../components';
import type { VendorInviteResponseMfa } from '../../api/generated/models';

/** The one-time invite material a successful invite/reinvite hands back. */
export type VendorSeed = {
  name: string;
  mfa: VendorInviteResponseMfa;
};

/**
 * The one-time MFA seed panel (F4 screen 8, legacy heading "MFA seed -
 * shown once"). The secret comes from the invite response the server
 * chose to show exactly once - it is never re-fetchable, so the card
 * exists only in component state and the Hide button drops it for good
 * (the vendor's own note renders verbatim).
 */
export function SeedCard({ seed, onHide }: { seed: VendorSeed; onHide: () => void }) {
  const { t } = useTranslation();
  return (
    <div
      className="flex flex-col gap-space-sm rounded-lg border border-primary/30 bg-surface-container-lowest px-space-md py-space-sm"
      data-testid="vendor-seed-card"
    >
      <div className="flex flex-wrap items-center gap-space-sm">
        <Chip tone="info">{t('vendor.seed.kicker')}</Chip>
        <span className="font-body-sm text-body-sm font-semibold text-on-surface">
          {t('vendor.seed.title', { name: seed.name })}
        </span>
        <span className="ml-auto">
          <Button type="button" variant="secondary" onClick={onHide}>
            {t('vendor.seed.hide')}
          </Button>
        </span>
      </div>
      <span className="font-body-sm text-body-sm text-on-surface-variant">
        {seed.mfa.note}
      </span>
      <code className="break-all font-code-sm text-code-sm text-on-surface">
        {seed.mfa.secret}
      </code>
      <code className="break-all font-code-sm text-code-sm text-outline">
        {seed.mfa.otpauth_uri}
      </code>
      <span className="font-code-sm text-code-sm text-outline">
        {t('vendor.seed.params', {
          digits: seed.mfa.digits,
          period: seed.mfa.period,
          algorithm: seed.mfa.algorithm,
        })}
      </span>
    </div>
  );
}
