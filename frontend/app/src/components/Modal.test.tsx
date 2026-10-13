import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { Modal } from './Modal';

describe('Modal', () => {
  it('renders the title as the dialog accessible name (brief §2)', () => {
    render(
      <Modal open onOpenChange={vi.fn()} title="Terminate session">
        <p>Confirm.</p>
      </Modal>,
    );
    expect(screen.getByRole('dialog', { name: 'Terminate session' })).toBeInTheDocument();
  });

  it('renders children in the body', () => {
    render(
      <Modal open onOpenChange={vi.fn()} title="Terminate">
        <p>Body text</p>
      </Modal>,
    );
    expect(screen.getByText('Body text')).toBeInTheDocument();
  });

  it('renders the footer action cluster', () => {
    render(
      <Modal
        open
        onOpenChange={vi.fn()}
        title="Terminate"
        footer={<button type="button">Confirm</button>}
      >
        <p>Body</p>
      </Modal>,
    );
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument();
  });

  it('calls onOpenChange(false) from the close button (brief §2: close ×)', () => {
    const onOpenChange = vi.fn();
    render(
      <Modal open onOpenChange={onOpenChange} title="Terminate" closeLabel="Close dialog">
        <p>Body</p>
      </Modal>,
    );
    const close = screen.getByRole('button', { name: 'Close dialog' });
    close.click();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('has no axe violations when open', async () => {
    const { baseElement } = render(
      <Modal open onOpenChange={vi.fn()} title="Terminate session">
        <p>Confirm.</p>
      </Modal>,
    );
    await expectNoAxeViolations(baseElement);
  });

  it('renders nothing when closed', () => {
    render(
      <Modal open={false} onOpenChange={vi.fn()} title="Terminate">
        <p>Body</p>
      </Modal>,
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
