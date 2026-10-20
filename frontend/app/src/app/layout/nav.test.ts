import { describe, expect, it } from 'vitest';

import { NAV_GROUPS, NAV_ITEMS } from './nav';

/**
 * ADR-0020 Decision 3 contract: every NAV_ITEMS path appears in exactly
 * one group (no orphan, no duplicate), so the six-group sidebar always
 * renders every route.
 */
describe('NAV_GROUPS (ADR-0020 Decision 3)', () => {
  it('covers every NAV_ITEMS path exactly once', () => {
    const paths = NAV_GROUPS.flatMap((group) => group.paths);
    expect(new Set(paths).size).toBe(NAV_ITEMS.length);
    expect(new Set(paths)).toEqual(new Set(NAV_ITEMS.map((item) => item.path)));
  });
});
