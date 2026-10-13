import type { Meta, StoryObj } from '@storybook/react-vite';

import { NotConnected, Value } from './HonestStates';

/** Wrapper so the honest-state helpers can be stories too. */
function HonestStatesDemo({
  showValue,
  showChip,
}: {
  showValue: boolean;
  showChip: boolean;
}) {
  return (
    <div className="flex flex-col gap-space-md">
      {showValue ? (
        <p className="font-body-md text-body-md text-on-surface">
          Elevated sessions: <Value value={null} />
        </p>
      ) : null}
      {showChip ? <NotConnected /> : null}
    </div>
  );
}

const meta = {
  title: 'Components/HonestStates',
  component: HonestStatesDemo,
  tags: ['autodocs'],
  args: { showValue: true, showChip: true },
} satisfies Meta<typeof HonestStatesDemo>;

export default meta;
type Story = StoryObj<typeof meta>;

/** Brief §3.2: absent data = em-dash, module = "not connected" chip. Never sample numbers. */
export const Default: Story = {};
