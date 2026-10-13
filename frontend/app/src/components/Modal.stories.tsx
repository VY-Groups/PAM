import { useState } from 'react';
import type { Meta, StoryObj } from '@storybook/react-vite';

import { Button } from './Button';
import { Modal } from './Modal';

/** Self-contained wrapper: keeps the dialog open/close state in React. */
function ModalDemo({
  title,
  children,
  closeLabel,
}: {
  title: string;
  children: React.ReactNode;
  closeLabel: string;
}) {
  const [open, setOpen] = useState(true);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Open dialog</Button>
      <Modal
        open={open}
        onOpenChange={setOpen}
        title={title}
        closeLabel={closeLabel}
        footer={
          <>
            <Button variant="secondary" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => setOpen(false)}>
              Terminate
            </Button>
          </>
        }
      >
        {children}
      </Modal>
    </>
  );
}

const meta = {
  title: 'Components/Modal',
  component: ModalDemo,
  tags: ['autodocs'],
  args: {
    title: 'Terminate session',
    closeLabel: 'Close dialog',
    children:
      'Session sess-482 on bastion-01 will be disconnected immediately. The operator needs it, so it will re-attach automatically.',
  },
} satisfies Meta<typeof ModalDemo>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Open: Story = {};
