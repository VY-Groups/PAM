import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { NotConnected, Value } from './HonestStates';

describe('Value', () => {
  it('renders the honest em-dash when value is null', () => {
    render(<Value value={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('renders the honest em-dash when value is undefined', () => {
    const { container } = render(<Value />);
    expect(container.textContent).toBe('—');
  });

  it('renders the honest em-dash for empty string (brief §3.2)', () => {
    const { container } = render(<Value value="" />);
    expect(container.textContent).toBe('—');
  });

  it('renders a real value when present', () => {
    render(<Value value={17} />);
    expect(screen.getByText('17')).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    const { container } = render(<Value value={null} />);
    await expectNoAxeViolations(container);
  });
});

describe('NotConnected', () => {
  it('renders the brief §3.2 default label', () => {
    render(<NotConnected />);
    expect(screen.getByText('not connected')).toBeInTheDocument();
  });

  it('has no axe violations', async () => {
    const { container } = render(<NotConnected />);
    await expectNoAxeViolations(container);
  });
});
