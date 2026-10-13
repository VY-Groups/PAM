import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { Button } from './Button';

describe('Button', () => {
  it('renders its label', () => {
    render(<Button>Reveal</Button>);
    expect(screen.getByRole('button', { name: 'Reveal' })).toBeInTheDocument();
  });

  it('fires onClick', () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Terminate</Button>);
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('applies primary variant classes by default (brief §2)', () => {
    render(<Button>Reveal</Button>);
    expect(screen.getByRole('button').className).toContain('bg-surface-container');
  });

  it('applies destructive variant classes (brief §2)', () => {
    render(<Button variant="destructive">Terminate</Button>);
    const btn = screen.getByRole('button');
    expect(btn.className).toContain('bg-error');
    expect(btn.className).toContain('text-on-error');
  });

  it('renders a leading material icon as decoration (ADR-0007, brief §5)', () => {
    render(<Button icon="key">Reveal</Button>);
    const icon = document.querySelector('.material-symbols-outlined');
    expect(icon).not.toBeNull();
    expect(icon).toHaveAttribute('aria-hidden', 'true');
  });

  it('icon-only button exposes an accessible name (brief §5)', () => {
    render(<Button icon="refresh" ariaLabel="Refresh" />);
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument();
  });

  it('is disabled when given (honest state: backend down, brief §3.2)', () => {
    render(<Button disabled>Reveal</Button>);
    expect(screen.getByRole('button')).toBeDisabled();
  });

  it('has no axe violations', async () => {
    const { container } = render(<Button icon="key">Reveal</Button>);
    await expectNoAxeViolations(container);
  });
});
