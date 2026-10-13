import { useTranslation } from 'react-i18next';

/**
 * The honest strangler state (plan §8): the route exists, the shell is
 * live, the screen itself migrates at F4 - and the legacy screen stays
 * reachable from here. No placeholder screenshots, no sample data.
 */
export function PendingScreen({
  titleKey,
  legacyHref,
}: {
  titleKey: string;
  legacyHref: string;
}) {
  const { t } = useTranslation();
  return (
    <section className="max-w-2xl flex flex-col gap-space-md pt-space-xl">
      <h1 className="font-headline-lg text-headline-lg text-on-surface">
        {t('pending.title', { feature: t(titleKey) })}
      </h1>
      <p className="font-body-md text-body-md text-on-surface-variant">
        {t('pending.body')}
      </p>
      <a
        href={legacyHref}
        className="self-start flex items-center gap-1.5 px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-label-md text-label-md transition-all shadow-sm"
      >
        <span className="material-symbols-outlined text-[18px]" aria-hidden="true">
          open_in_new
        </span>
        {t('pending.openLegacy')}
      </a>
    </section>
  );
}
