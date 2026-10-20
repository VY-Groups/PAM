import { useTranslation } from 'react-i18next';

import { Button } from '../../components/Button';
import { BreakGlassButton } from './BreakGlassButton';

/**
 * Top bar (ADR-0020 Decision 1): slim controls row - the responsive
 * hamburger (below lg), the live-session console toggle (opens the
 * recording-inspector drawer, ADR-0020 Decision 2), and the Break-Glass
 * shortcut. The identity chip and sign-out moved to the sidebar footer.
 */
export function TopBar({
  navOpen,
  onToggleNav,
  consoleOpen,
  onToggleConsole,
}: {
  navOpen: boolean;
  onToggleNav: () => void;
  consoleOpen: boolean;
  onToggleConsole: () => void;
}) {
  const { t } = useTranslation();

  return (
    <header className="fixed top-0 left-0 lg:left-64 right-0 h-16 bg-surface-container-lowest/90 backdrop-blur-md border-b border-outline-variant/25 z-40 flex items-center justify-between px-space-xl">
      <div className="flex items-center gap-space-md flex-1 max-w-2xl">
        <Button
          variant="secondary"
          icon="menu"
          ariaLabel={t('shell.navToggle')}
          aria-expanded={navOpen}
          aria-controls="app-sidebar"
          className="lg:hidden"
          onClick={onToggleNav}
        />
        <Button
          variant="secondary"
          icon="terminal"
          ariaLabel={t('shell.consoleToggle')}
          aria-expanded={consoleOpen}
          aria-controls={consoleOpen ? 'console-drawer' : undefined}
          onClick={onToggleConsole}
        />
      </div>
      <div className="flex items-center gap-space-md">
        <BreakGlassButton />
      </div>
    </header>
  );
}
