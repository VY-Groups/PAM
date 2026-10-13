import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { StatusDot } from './StatusDot';

describe('StatusDot', () => {
  it('renders a 1.5 dot with pulse when live (as-built, brief §2)', () => {
    const { container } = render(<StatusDot state="live" />);
    const dot = container.firstElementChild!;
    expect(dot.className).toContain('w-1.5');
    expect(dot.className).toContain('h-1.5');
    expect(dot.className).toContain('rounded-full');
    expect(dot.className).toContain('animate-pulse');
  });

  it('is flat (no pulse) when static (brief §2)', () => {
    const { container } = render(<StatusDot state="ok" />);
    expect(container.firstElementChild!.className).not.toContain('animate-pulse');
  });

  it('is decorative - always paired with text (brief §5)', () => {
    const { container } = render(<StatusDot state="error" />);
    expect(container.firstElementChild).toHaveAttribute('aria-hidden', 'true');
  });

  it('has no axe violations', async () => {
    const { container } = render(<StatusDot state="live" />);
    await expectNoAxeViolations(container);
  });
});
