import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { Chip } from './Chip';

describe('Chip', () => {
  it('renders its label', () => {
    render(<Chip>Active</Chip>);
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('applies the info tone classes (brief §2)', () => {
    render(<Chip tone="info">Active</Chip>);
    const chip = screen.getByText('Active');
    expect(chip.className).toContain('bg-surface-container');
    expect(chip.className).toContain('text-primary');
  });

  it('applies the inactive tone classes (brief §2)', () => {
    render(<Chip tone="inactive">Archived</Chip>);
    expect(screen.getByText('Archived').className).toContain('text-outline');
  });

  it('has no axe violations', async () => {
    const { container } = render(<Chip>Active</Chip>);
    await expectNoAxeViolations(container);
  });
});
