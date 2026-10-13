import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { Tabs } from './Tabs';

const tabs = [
  { value: 'sessions', label: 'Sessions', content: <p>Sessions panel</p> },
  { value: 'approvals', label: 'Approvals', content: <p>Approvals panel</p> },
];

describe('Tabs', () => {
  it('renders one tab per item with an accessible list name (brief §2)', () => {
    render(<Tabs tabs={tabs} label="Workspace views" />);
    expect(screen.getByRole('tablist', { name: 'Workspace views' })).toBeInTheDocument();
    expect(screen.getAllByRole('tab')).toHaveLength(2);
  });

  it('activates the first tab by default', () => {
    render(<Tabs tabs={tabs} label="Views" />);
    expect(screen.getByRole('tab', { name: 'Sessions' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByText('Sessions panel')).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    const { container } = render(<Tabs tabs={tabs} label="Views" />);
    await expectNoAxeViolations(container);
  });
});
