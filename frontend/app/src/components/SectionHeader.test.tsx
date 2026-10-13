import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { SectionHeader } from './SectionHeader';

describe('SectionHeader', () => {
  it('renders the title as a heading (brief §2, headline-lg)', () => {
    render(<SectionHeader title="Credential Vault" />);
    const heading = screen.getByRole('heading', { name: 'Credential Vault' });
    expect(heading.className).toContain('font-headline-lg');
  });

  it('renders the subtitle when provided', () => {
    render(<SectionHeader title="Vault" subtitle="Inventory and rotation" />);
    expect(screen.getByText('Inventory and rotation')).toBeInTheDocument();
  });

  it('renders the right-aligned action cluster', () => {
    render(
      <SectionHeader
        title="Vault"
        actions={<button type="button">Add credential</button>}
      />,
    );
    expect(screen.getByRole('button', { name: 'Add credential' })).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    const { container } = render(<SectionHeader title="Vault" subtitle="Sub" />);
    await expectNoAxeViolations(container);
  });
});
