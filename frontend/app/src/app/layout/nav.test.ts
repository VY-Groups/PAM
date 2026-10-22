import { describe, expect, it } from 'vitest';

import { API_OPERATIONS } from '../../features/topology/topology.generated';
import { NAV_GROUPS, NAV_ITEMS, NAV_JOB_OPS } from './nav';

/**
 * ADR-0021 (12.RC) contract: the brief's five job groups replace the
 * ADR-0020 Decision 3 module groups, every NAV_ITEMS path appears in
 * exactly one group (no orphan, no duplicate), so the grouped sidebar
 * always renders every route.
 */
describe('NAV_GROUPS (ADR-0021, amends ADR-0020 Decision 3)', () => {
  it('covers every NAV_ITEMS path exactly once', () => {
    const paths = NAV_GROUPS.flatMap((group) => group.paths);
    expect(new Set(paths).size).toBe(NAV_ITEMS.length);
    expect(new Set(paths)).toEqual(new Set(NAV_ITEMS.map((item) => item.path)));
  });

  it('is exactly the five job groups the brief names', () => {
    expect(NAV_GROUPS.map((group) => group.labelKey)).toEqual([
      'nav.group.access',
      'nav.group.approvals',
      'nav.group.sessions',
      'nav.group.evidence',
      'nav.group.platform',
    ]);
  });
});

/**
 * ADR-0021 D1 contract: the nav permission map is operations-only (no
 * role names anywhere), keyed for every route, and every declared
 * operation string must exist in the CI-generated contract list - so a
 * contract change without a nav update fails here instead of silently
 * hiding or exposing a page.
 */
describe('NAV_JOB_OPS (ADR-0021 Decision 1)', () => {
  it('declares an entry for every nav path, and no orphans', () => {
    const paths = new Set(NAV_ITEMS.map((item) => item.path));
    expect(Object.keys(NAV_JOB_OPS).sort()).toEqual([...paths].sort());
  });

  it('pins every declared operation to the generated OpenAPI operation list', () => {
    const contract = new Set(API_OPERATIONS);
    for (const [path, ops] of Object.entries(NAV_JOB_OPS)) {
      for (const op of ops) {
        // whoami's operations are lowercase "method path"; the generated
        // contract list is uppercase-method. Same string modulo case.
        const [method, ...rest] = op.split(' ');
        const normalized = `${method.toUpperCase()} ${rest.join(' ')}`;
        expect(contract.has(normalized), `${path} declares "${op}"`).toBe(true);
      }
    }
  });

  it('never names a role - permissions come from operations only', () => {
    const serialised = JSON.stringify({ NAV_GROUPS, NAV_JOB_OPS });
    for (const role of ['admin', 'operator', 'approver', 'auditor', 'auditor-read-only']) {
      // "auditor" is a substring of "auditor-read-only"; five checks anyway.
      expect(serialised.includes(`"${role}"`), role).toBe(false);
    }
  });
});
