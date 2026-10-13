import type { Meta, StoryObj } from '@storybook/react-vite';

import { Chip } from './Chip';

const meta = {
  title: 'Components/Chip',
  component: Chip,
  tags: ['autodocs'],
  args: { children: 'Active' },
} satisfies Meta<typeof Chip>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Info: Story = {};

export const Inactive: Story = {
  args: { tone: 'inactive', children: 'Revoked' },
};
