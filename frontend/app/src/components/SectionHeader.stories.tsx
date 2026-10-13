import type { Meta, StoryObj } from '@storybook/react-vite';

import { Button } from './Button';
import { SectionHeader } from './SectionHeader';

const meta = {
  title: 'Components/SectionHeader',
  component: SectionHeader,
  tags: ['autodocs'],
  args: {
    title: 'Credential Vault',
    subtitle: 'Inventory, checkout and rotation',
  },
} satisfies Meta<typeof SectionHeader>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {};

export const WithActions: Story = {
  render: (args) => (
    <SectionHeader {...args} actions={<Button icon="add">Add credential</Button>} />
  ),
};
