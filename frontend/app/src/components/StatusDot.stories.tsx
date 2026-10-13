import type { Meta, StoryObj } from '@storybook/react-vite';

import { StatusDot } from './StatusDot';

const meta = {
  title: 'Components/StatusDot',
  component: StatusDot,
  tags: ['autodocs'],
} satisfies Meta<typeof StatusDot>;

export default meta;
type Story = StoryObj<typeof meta>;

/** Live: bg-primary + animate-pulse (as-built). */
export const Live: Story = {
  args: { state: 'live' },
};

/** Static: flat, no pulse (brief §2). */
export const StaticOk: Story = {
  args: { state: 'ok' },
};

export const Error: Story = {
  args: { state: 'error' },
};

export const Muted: Story = {
  args: { state: 'muted' },
};
