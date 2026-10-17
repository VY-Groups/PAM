import { useTranslation } from 'react-i18next';

import { SectionHeader, Tabs } from '../../components';
import { ApiSurfaceSection } from './ApiSurfaceSection';
import { BackendMapSection } from './BackendMapSection';
import { FrontendMapSection } from './FrontendMapSection';
import { NetworkSection } from './NetworkSection';
import { WorkflowsSection } from './WorkflowsSection';

/**
 * System & Workflow Maps (ADR-0013, ordered 2026-10-16): five views of
 * the real system - frontend routes, backend packages, the contract's
 * API surface and the curated lifecycles are EXTRACTED from the
 * committed tree (drift-gated in CI), the network posture is FETCHED
 * from the running node (honest loading/error states, never a drawn
 * memory of it). Design-system primitives only; Radix unmounts
 * inactive panels, so each view loads when opened.
 */
export function TopologyPage() {
  const { t } = useTranslation();
  return (
    <div className="space-y-space-lg">
      <SectionHeader
        title={t('topology.page.title')}
        subtitle={t('topology.page.subtitle')}
      />
      <Tabs
        label={t('topology.page.tabsLabel')}
        defaultValue="frontend"
        tabs={[
          {
            value: 'frontend',
            label: t('topology.page.viewFrontend'),
            content: <FrontendMapSection />,
          },
          {
            value: 'backend',
            label: t('topology.page.viewBackend'),
            content: <BackendMapSection />,
          },
          {
            value: 'api',
            label: t('topology.page.viewApi'),
            content: <ApiSurfaceSection />,
          },
          {
            value: 'network',
            label: t('topology.page.viewNetwork'),
            content: <NetworkSection />,
          },
          {
            value: 'workflows',
            label: t('topology.page.viewWorkflows'),
            content: <WorkflowsSection />,
          },
        ]}
      />
    </div>
  );
}
