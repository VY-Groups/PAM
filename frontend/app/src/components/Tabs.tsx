import * as TabsPrimitive from '@radix-ui/react-tabs';
import type { ReactNode } from 'react';

export interface TabItem {
  value: string;
  label: string;
  content: ReactNode;
}

export interface TabsProps {
  tabs: TabItem[];
  defaultValue?: string;
  /** Accessible name for the tab list (axe). */
  label: string;
  className?: string;
}

/**
 * Tabs (brief §2): pill group; active = bg-surface-container-high font-semibold.
 * Radix Tabs primitive per ADR-0003 (arrow-key navigation, aria-controls).
 */
export function Tabs({ tabs, defaultValue, label, className = '' }: TabsProps) {
  const initial = defaultValue ?? tabs[0]?.value;
  if (!initial) return null;
  return (
    <TabsPrimitive.Root defaultValue={initial} className={className}>
      <TabsPrimitive.List
        aria-label={label}
        className="flex items-center gap-space-xs rounded-lg bg-surface-container-low p-space-xs"
      >
        {tabs.map((tab) => (
          <TabsPrimitive.Trigger
            key={tab.value}
            value={tab.value}
            className="rounded px-space-md py-space-xs font-label-md text-label-md text-on-surface-variant data-[state=active]:bg-surface-container-high data-[state=active]:text-on-surface data-[state=active]:font-semibold focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary-container"
          >
            {tab.label}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {tabs.map((tab) => (
        <TabsPrimitive.Content
          key={tab.value}
          value={tab.value}
          className="mt-space-md focus-visible:outline-none"
        >
          {tab.content}
        </TabsPrimitive.Content>
      ))}
    </TabsPrimitive.Root>
  );
}
