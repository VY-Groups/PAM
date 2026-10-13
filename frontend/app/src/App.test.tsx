import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { App } from './App';

describe('App (F1 scaffold)', () => {
  it('renders the VY-PAM brand and the F1 state', () => {
    render(<App />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('VY-PAM');
    expect(screen.getByText(/F1 foundations/)).toBeInTheDocument();
  });

  it('contains no sample-brand strings (F0 invariant)', () => {
    const { container } = render(<App />);
    expect(container.textContent).not.toMatch(/Aegis|Stitch/i);
  });
});
