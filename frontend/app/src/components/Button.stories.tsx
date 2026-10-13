import type { Meta, StoryObj } from '@storybook/react-vite';

import { Button } from './Button';

const meta = {
  title: 'Components/Button',
  component: Button,
  tags: ['autodocs'],
  args: { children: 'Reveal' },
} satisfies Meta<typeof Button>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Primary: Story = {};

export const Secondary: Story = {
  args: { variant: 'secondary', children: 'Cancel' },
};

export const Destructive: Story = {
  args: { variant: 'destructive', children: 'Terminate session' },
};

export const WithLeadingIcon: Story = {
  args: { icon: 'key' },
};

/** Icon-only buttons must carry an accessible name (brief §5). */
export const IconOnly: Story = {
  args: { children: undefined, icon: 'refresh', ariaLabel: 'Refresh' },
};

/** Honest disabled state - e.g. backend down (brief §3.2). */
export const Disabled: Story = {
  args: { disabled: true, children: 'Reveal' },
};
