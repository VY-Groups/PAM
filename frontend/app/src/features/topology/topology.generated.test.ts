import fs from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

import { NAV_ITEMS } from '../../app/layout/nav';
import { PendingScreen } from '../../app/PendingScreen';
import { routes as routeTable } from '../../app/router';
import {
  API_METHOD_COUNTS,
  API_OPERATIONS,
  API_OPERATION_COUNT,
  API_PATH_COUNT,
  API_TAGS,
  BACKEND_PACKAGES,
  FRONTEND_ROUTES,
} from './topology.generated';
import { WORKFLOWS } from './workflows';

/**
 * Verification layer 2 + 3 of ADR-0013: this file re-derives every
 * source with its own readers - the nav table and the router array are
 * IMPORTED from the real modules, the contract is re-parsed with yaml,
 * the backend trees are re-walked from disk - and asserts the committed
 * `topology.generated.ts` equals them. The extractor therefore cannot
 * silently drift from reality: CI's regenerate-and-diff step proves the
 * committed file matches the script, and these tests prove the script's
 * output matches the sources. Layer 3 additionally pins the curated
 * workflows: every step's contract operation and every evidence
 * reference must exist, so no diagram step can describe something the
 * product neither serves nor proves.
 *
 * The re-derivations below intentionally repeat the extractor's
 * documented POLICY (test/conftest exclusions, first-tag grouping,
 * uppercase methods) in a separate implementation - same rules, second
 * writer, so a bug in one is caught by the other.
 */

const REPO = path.resolve(process.cwd(), '..', '..');
const read = (rel: string) => fs.readFileSync(path.join(REPO, rel), 'utf8');

/* ------------------------- independently parsed contract (yaml re-parse) */

const spec = YAML.parse(read('apis/openapi.yaml')) as {
  paths: Record<string, Record<string, { tags?: string[]; summary?: string }>>;
};

interface SpecOp {
  method: string;
  path: string;
  summary: string | null;
}

const specOperations: string[] = [];
const specMethodCounts: Record<string, number> = {};
const specTagGroups: Array<{ name: string; operations: SpecOp[] }> = [];
const specTagIndex = new Map<string, { name: string; operations: SpecOp[] }>();

for (const [p, item] of Object.entries(spec.paths)) {
  for (const [method, op] of Object.entries(item)) {
    if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue;
    const M = method.toUpperCase();
    specOperations.push(`${M} ${p}`);
    specMethodCounts[M] = (specMethodCounts[M] ?? 0) + 1;
    const tagName = (op.tags ?? ['(none)'])[0];
    let group = specTagIndex.get(tagName);
    if (!group) {
      group = { name: tagName, operations: [] };
      specTagIndex.set(tagName, group);
      specTagGroups.push(group);
    }
    group.operations.push({ method: M, path: p, summary: op.summary ?? null });
  }
}
const specOperationSet = new Set(specOperations);

/* ---------------------------------- independently walked backend policy */

const isTestPath = (rel: string) =>
  rel
    .split('/')
    .some((seg) => seg === 'tests' || seg === '__pycache__' || seg === '.pytest_cache') ||
  path.posix.basename(rel).startsWith('test_') ||
  path.posix.basename(rel) === 'conftest.py';

function walkPy(dir: string): string[] {
  const found: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...walkPy(full));
    else if (entry.name.endsWith('.py')) found.push(full);
  }
  return found;
}

/** Is this route element the pending-screen fallback (not a real page)? */
function isPendingElement(node: unknown): boolean {
  return (
    typeof node === 'object' &&
    node !== null &&
    (node as { type?: unknown }).type === PendingScreen
  );
}

/* --------------------------------------------------- layer 2: the sources */

describe('topology.generated equals its sources (ADR-0013 layer 2)', () => {
  it('mirrors NAV_ITEMS exactly - path, label, icon, legacy href, danger', () => {
    for (const item of NAV_ITEMS) {
      const row = FRONTEND_ROUTES.find((r) => r.path === item.path);
      expect(row, `nav item ${item.path} missing from the map`).toBeDefined();
      expect(row?.labelKey).toBe(item.labelKey);
      expect(row?.icon).toBe(item.icon);
      expect(row?.legacyHref).toBe(item.legacyHref ?? null);
      expect(row?.danger).toBe(item.danger === true);
    }
  });

  it('marks every implemented router path live, and only pending nav items pending', () => {
    // The router table carries both feature routes and the pending-screen
    // fallbacks - only the former are `live` rows of the map.
    const livePaths = routeTable
      .flatMap((r) => [r, ...(r.children ?? [])])
      .filter(
        (r) =>
          typeof r.path === 'string' &&
          r.path.startsWith('/') &&
          !isPendingElement(r.element),
      )
      .map((r) => r.path as string);
    for (const p of livePaths) {
      const row = FRONTEND_ROUTES.find((r) => r.path === p);
      expect(row, `route ${p} missing from the map`).toBeDefined();
      expect(row?.state).toBe('live');
    }
    const liveSet = new Set(livePaths);
    const pendingPaths = NAV_ITEMS.filter((i) => !liveSet.has(i.path))
      .map((i) => i.path)
      .sort();
    expect(
      FRONTEND_ROUTES.filter((r) => r.state === 'pending')
        .map((r) => r.path)
        .sort(),
    ).toEqual(pendingPaths);
    // One map row per nav item plus the non-sidebar routes (login, ...).
    expect(FRONTEND_ROUTES.length).toBeGreaterThanOrEqual(NAV_ITEMS.length);
  });

  it('upholds the ADR-0013 invariant: no legacy href means implemented', () => {
    for (const row of FRONTEND_ROUTES) {
      if (row.state === 'pending') expect(row.legacyHref).toBeTruthy();
      if (!row.legacyHref) expect(row.state).toBe('live');
    }
  });

  it('resolves every rendered endpoint against the real contract', () => {
    for (const row of FRONTEND_ROUTES) {
      for (const endpoint of row.endpoints) {
        expect(specOperationSet.has(endpoint), `${row.path}: ${endpoint}`).toBe(true);
      }
    }
  });

  it('equals the re-parsed openapi.yaml surface (counts, methods, tags)', () => {
    expect(API_PATH_COUNT).toBe(Object.keys(spec.paths).length);
    expect(API_OPERATION_COUNT).toBe(specOperations.length);
    expect(API_METHOD_COUNTS).toEqual(specMethodCounts);
    expect(API_OPERATIONS).toEqual(specOperations);
    expect(API_TAGS).toEqual(specTagGroups);
  });

  it('mirrors the backend trees on disk, with edges that exist', () => {
    const repoPosix = REPO.split(path.sep).join('/');
    for (const pkg of BACKEND_PACKAGES) {
      const disk = walkPy(path.join(REPO, pkg.root))
        .map((f) => path.posix.relative(repoPosix, f.split(path.sep).join('/')))
        .filter((rel) => !isTestPath(rel))
        .map((rel) => path.posix.relative(pkg.root, rel))
        .sort();
      expect(pkg.files.map((f) => f.path).sort(), pkg.name).toEqual(disk);
      for (const file of pkg.files) {
        const text = read(`${pkg.root}/${file.path}`);
        expect(file.lines, `${pkg.name}/${file.path} lines`).toBe(text.split('\n').length);
        for (const target of file.imports) {
          expect(
            fs.existsSync(path.join(REPO, target)),
            `${pkg.name}/${file.path} -> ${target}`,
          ).toBe(true);
        }
      }
    }
  });
});

/* ------------------------------------------ layer 3: curated workflows */

describe('workflows are contract-true and provable (ADR-0013 layer 3)', () => {
  it('every step is a real contract operation', () => {
    for (const workflow of WORKFLOWS) {
      for (const step of workflow.steps) {
        expect(
          specOperationSet.has(step.operation),
          `${workflow.id}: ${step.operation} not in openapi.yaml`,
        ).toBe(true);
      }
    }
  });

  it('every evidence reference exists on disk with its marker text', () => {
    for (const workflow of WORKFLOWS) {
      for (const step of workflow.steps) {
        const evidence = path.join(REPO, step.evidence.file);
        expect(fs.existsSync(evidence), `missing ${step.evidence.file}`).toBe(true);
        expect(
          fs.readFileSync(evidence, 'utf8').includes(step.evidence.contains),
          `${workflow.id}: "${step.evidence.contains}" not in ${step.evidence.file}`,
        ).toBe(true);
      }
    }
  });
});
