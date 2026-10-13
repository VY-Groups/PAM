import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';

import { Button } from '../../components/Button';
import { StatusDot } from '../../components/StatusDot';
import { useAuth } from '../providers/useAuth';
import { BreakGlassButton } from './BreakGlassButton';

/**
 * Top bar (as-built header classes: fixed, h-16, backdrop blur, left-64).
 * F3 carries the honest identity chip (real `whoami` data: principal +
 * role) and sign-out; the legacy search / stream chips follow with their
 * features (F4).
 */
export function TopBar() {
  const { t } = useTranslation();
  const { whoami, logout } = useAuth();
  const navigate = useNavigate();

  const onSignOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <header className="fixed top-0 left-64 right-0 h-16 bg-surface-container-lowest/90 backdrop-blur-md border-b border-outline-variant/25 z-40 flex items-center justify-between px-space-xl">
      <div className="flex items-center gap-space-md flex-1 max-w-2xl" />
      <div className="flex items-center gap-space-md">
        {whoami ? (
          <div className="flex items-center gap-space-sm px-space-sm py-1 rounded bg-surface-container border border-outline-variant/30 font-code-sm text-code-sm text-on-surface">
            <StatusDot state="ok" />
            <span>{whoami.principal}</span>
            <span className="text-outline">|</span>
            <span className="text-outline font-semibold">
              {t('shell.roleBadge', { role: whoami.role })}
            </span>
          </div>
        ) : null}
        <BreakGlassButton />
        <Button variant="secondary" icon="logout" onClick={() => void onSignOut()}>
          {t('shell.signOut')}
        </Button>
      </div>
    </header>
  );
}
