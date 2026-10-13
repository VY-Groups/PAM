import type { Meta, StoryObj } from '@storybook/react-vite';

import { KpiCard } from './KpiCard';

const meta = {
  title: 'Components/KpiCard',
  component: KpiCard,
  tags: ['autodocs'],
  args: { label: 'Active Privileged Sessions', value: null },
} satisfies Meta<typeof KpiCard>;

export default meta;
type Story = StoryObj<typeof meta>;

/** Honest empty state: no data renders the em-dash, never a sample number (brief §3.2). */
export const Empty: Story = {};

export const WithValue: Story = {
  args: { value: 17, footer: 'reported by the broker' },
};

export const PrimaryContainerAccent: Story = {
  args: { accent: 'primary-container', value: 3 },
};

export const ErrorAccent: Story = {
  args: { accent: 'error', label: 'Denied Elevation Attempts', value: 2 },
};
