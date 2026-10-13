import axe from 'axe-core';
import { expect } from 'vitest';

/**
 * Run axe-core against a rendered container and fail the test on any
 * violation (plan F2 exit: every component has an axe check; ADR-0008).
 *
 * The `color-contrast` rule needs a real layout/paint engine and cannot
 * run in jsdom - it is explicitly disabled here and covered by the
 * Storybook a11y panel (real browser) + the F6 accessibility pass.
 */
export async function expectNoAxeViolations(container: Element): Promise<void> {
  const results = await axe.run(container, {
    rules: {
      'color-contrast': { enabled: false },
    },
  });
  const summary = results.violations.map(
    (v) =>
      `${v.id}: ${v.help} (${v.nodes.length} node(s)) -> ${v.nodes[0]?.target.join(' ') ?? ''}`,
  );
  expect(summary).toEqual([]);
}
