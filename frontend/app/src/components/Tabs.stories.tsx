import type { Meta, StoryObj } from '@storybook/react-vite';

import { KpiCard } from './KpiCard';
import { Tabs } from './Tabs';

const meta = {
  title: 'Components/Tabs',
  component: Tabs,
  tags: ['autodocs'],
  args: {
    label: 'Workspace views',
    tabs: [
      { value: 'sessions', label: 'Sessions', content: <p>Sessions panel</p> },
      { value: 'approvals', label: 'Approvals', content: <p>Approvals panel</p> },
    ],
  },
} satisfies Meta<typeof Tabs>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {};

/** Honest state inside a tab: absent values render the em-dash (brief §3.2). */
export const WithHonestContent: Story = {
  args: {
    tabs: [
      {
        value: 'sessions',
        label: 'Sessions',
        content: <KpiCard label="Active Privileged Sessions" value={null} />,
      },
      { value: 'approvals', label: 'Approvals', content: <p>No approvals requested</p> },
    ],
  },
};
