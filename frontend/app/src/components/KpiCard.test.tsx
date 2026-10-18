import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { KpiCard } from './KpiCard';

describe('KpiCard', () => {
  it('renders its label (font-label-md, brief §2)', () => {
    render(<KpiCard label="Active Privileged Sessions" value={null} />);
    const label = screen.getByText('Active Privileged Sessions');
    expect(label.className).toContain('font-label-md');
  });

  it('renders the honest em-dash when there is no value (brief §3.2)', () => {
    const { container } = render(<KpiCard label="Sessions" value={null} />);
    expect(container.textContent).toContain('—');
  });

  it('renders the real value when present', () => {
    render(<KpiCard label="Sessions" value={17} />);
    expect(screen.getByText('17')).toBeInTheDocument();
  });

  it('renders the 4px accent bar (brief §2)', () => {
    const { container } = render(<KpiCard label="S" value={null} accent="tertiary" />);
    const bar = container.querySelector('.absolute.top-0');
    expect(bar).not.toBeNull();
    expect(bar!.className).toContain('h-1');
    expect(bar!.className).toContain('bg-tertiary');
    expect(bar).toHaveAttribute('aria-hidden', 'true');
  });

  it('renders footer when provided (body-sm, brief §2)', () => {
    render(<KpiCard label="S" value={null} footer="as of 12:00" />);
    expect(screen.getByText('as of 12:00').className).toContain('font-body-sm');
  });

  it('puts valueDataRole on the value span alone (settings posture tiles)', () => {
    const { container } = render(
      <KpiCard
        label="Peers"
        value={2}
        valueDataRole="cluster-tile-peers"
        footer="2 healthy"
      />,
    );
    const hook = container.querySelector('[data-role="cluster-tile-peers"]');
    expect(hook).not.toBeNull();
    expect(hook!.textContent).toBe('2');
    expect(hook!.querySelector('[data-role]')).toBeNull();
  });

  it('has no axe violations', async () => {
    const { container } = render(<KpiCard label="Sessions" value={null} />);
    await expectNoAxeViolations(container);
  });
});
