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

/* ---------------------- mermaid docs: the user-facing diagram artifacts */

describe('mermaid docs under docs/architecture (ADR-0013)', () => {
  const doc = (name: string) =>
    fs.readFileSync(path.join(REPO, 'docs', 'architecture', name), 'utf8');

  it('frontend-map.md carries every route, endpoint and legacy link', () => {
    const md = doc('frontend-map.md');
    expect(md).toContain('```mermaid');
    for (const row of FRONTEND_ROUTES) {
      expect(md, `route ${row.path}`).toContain(row.path);
      for (const ep of row.endpoints) expect(md, `${row.path} -> ${ep}`).toContain(ep);
      if (row.state === 'pending')
        expect(md, row.path).toContain(`legacy: ${row.legacyHref}`);
    }
  });

  it('backend-map.md mirrors the same files, sizes and edge count', () => {
    const md = doc('backend-map.md');
    let edges = 0;
    for (const pkg of BACKEND_PACKAGES) {
      for (const file of pkg.files) {
        expect(md, `${pkg.name}/${file.path}`).toContain(
          `${file.path} - ${file.lines} lines`,
        );
        edges += file.imports.length;
      }
    }
    expect(md.split(' --> ').length - 1).toBe(edges);
  });

  it('api-surface.md carries the counts and every contract operation', () => {
    const md = doc('api-surface.md');
    expect(md).toContain(`${API_PATH_COUNT} paths / ${API_OPERATION_COUNT} operations`);
    for (const op of API_OPERATIONS) expect(md, op).toContain(op);
  });

  it('network-posture.md wires the three live hooks to their cards', () => {
    const md = doc('network-posture.md');
    for (const [hook, endpoint] of [
      ['useHealth', 'GET /health'],
      ['useClusterOverview', 'GET /api/v1/cluster'],
      ['useTopologyIntegrations', 'GET /api/v1/integrations/status'],
    ] as const) {
      expect(md, hook).toContain(`-->|${hook}|`);
      expect(md, endpoint).toContain(endpoint);
    }
  });

  it('workflows.md sequences every step with its label and proof', () => {
    const md = doc('workflows.md');
    expect(md.split('sequenceDiagram').length - 1).toBe(WORKFLOWS.length);
    for (const workflow of WORKFLOWS) {
      for (const step of workflow.steps) {
        expect(md, step.operation).toContain(`UI->>API: ${step.operation}`);
        expect(md, step.evidence.file).toContain(
          `${step.evidence.file} :: ${step.evidence.contains}`,
        );
      }
    }
  });
});

/* -------------- architecture explorer: the interactive HTML artifact */

describe('architecture explorer under docs/architecture (ADR-0014)', () => {
  const html = read('docs/architecture/architecture-explorer.html');

  /** The generator emits DATA as exactly one line; parse that line. */
  interface ExplorerData {
    paths: number;
    domains: Array<[string, string]>;
    passive: string[];
    tags: Array<{ n: string; o: number; w: number; s: string[] }>;
    routes: Array<{ n: string; live: boolean; t: string[] }>;
    packages: Array<{
      n: string;
      root: string;
      m: Array<{ n: string; l: number }>;
      e: Array<[number, number]>;
      b: { x: number; y: number; w: number; h: number; c: number; col: string };
    }>;
    workflows: Array<{
      id: string;
      title: string;
      subtitle: string;
      steps: Array<{ op: string; label: string; note: string | null }>;
    }>;
  }

  const dataLine = html.split(/\r?\n/).find((l) => /^\s*const DATA = /.test(l));
  if (!dataLine) throw new Error('explorer: DATA line missing');
  const data = JSON.parse(
    dataLine.replace(/^\s*const DATA = /, '').replace(/;\s*$/, ''),
  ) as ExplorerData;

  // The passive Network-posture reads, pinned like the ADR-0013 network
  // test: the wired rule treats them as overview-only (state 1).
  const PASSIVE = ['GET /health', 'GET /api/v1/cluster', 'GET /api/v1/integrations/status'];

  // First-tag index, rebuilt from the independently parsed contract.
  const tagOfOp = new Map<string, string>();
  for (const group of specTagGroups) {
    for (const op of group.operations) tagOfOp.set(`${op.method} ${op.path}`, group.name);
  }

  it('is a consumed generation: banner present, placeholder gone', () => {
    expect(html).toContain('AUTO-GENERATED OUTPUT when rendered');
    expect(html).not.toContain('__DATA__');
    expect(data.paths).toBe(API_PATH_COUNT);
  });

  it('tag rows equal the re-parsed contract (first-tag grouping)', () => {
    expect(data.tags.map((t) => t.n)).toEqual(specTagGroups.map((g) => g.name));
    let sum = 0;
    for (const t of data.tags) {
      const group = specTagIndex.get(t.n);
      expect(group, t.n).toBeDefined();
      expect(t.o, t.n).toBe(group!.operations.length);
      sum += t.o;
      expect(t.s, t.n).toEqual(
        group!.operations.slice(0, 3).map((op) => `${op.method} ${op.path}`),
      );
      expect(t.w, t.n).toBeGreaterThanOrEqual(0);
      expect(t.w, t.n).toBeLessThanOrEqual(2);
    }
    expect(sum).toBe(API_OPERATION_COUNT);
  });

  it('route rows equal FRONTEND_ROUTES with their tags re-derived', () => {
    expect(data.routes).toHaveLength(FRONTEND_ROUTES.length);
    FRONTEND_ROUTES.forEach((row, i) => {
      const route = data.routes[i];
      expect(route.n, row.path).toBe(
        row.state === 'pending' ? `${row.path.slice(1)} (legacy page)` : row.path.slice(1),
      );
      expect(route.live, row.path).toBe(row.state === 'live');
      const expectedTags =
        row.state === 'live'
          ? specTagGroups
              .map((g) => g.name)
              .filter((name) => row.endpoints.some((ep) => tagOfOp.get(ep) === name))
          : []; // pending: legacy page, no generated-client calls
      expect(route.t, row.path).toEqual(expectedTags);
    });
  });

  it('wired states follow the ADR-0014 rule, re-derived independently', () => {
    expect(data.passive).toEqual(PASSIVE);
    const driven = new Map<string, number>();
    for (const row of FRONTEND_ROUTES) {
      if (row.state !== 'live') continue;
      for (const ep of row.endpoints) {
        const tag = tagOfOp.get(ep);
        expect(tag, `${row.path}: ${ep}`).toBeDefined();
        if (!PASSIVE.includes(ep)) driven.set(tag!, (driven.get(tag!) ?? 0) + 1);
      }
    }
    for (const t of data.tags) {
      const count = driven.get(t.n) ?? 0;
      const covered = FRONTEND_ROUTES.some(
        (row) =>
          row.state === 'live' && row.endpoints.some((ep) => tagOfOp.get(ep) === t.n),
      );
      expect(t.w, t.n).toBe(!covered ? 0 : count > 0 ? 2 : 1);
    }
  });

  it('package grids equal BACKEND_PACKAGES and their boxes fit every module', () => {
    expect(data.packages.map((p) => p.n)).toEqual([
      'phase2_license_server',
      'pam_master',
      'ipam_licensing',
    ]);
    for (const p of data.packages) {
      const src = BACKEND_PACKAGES.find((pkg) => pkg.name === p.n);
      expect(src, p.n).toBeDefined();
      expect(p.root).toBe(src!.root);
      expect(p.m.map((m) => m.n)).toEqual(
        src!.files.map((f) => f.path.replace(/\.py$/, '')),
      );
      expect(p.m.map((m) => m.l)).toEqual(src!.files.map((f) => f.lines));
      // Edges re-derived with the extractor's documented mapping policy
      // (repo-relative target, stripped of this package's root).
      const indexOf = new Map(src!.files.map((f, i) => [f.path, i]));
      const expectedEdges: Array<[number, number]> = [];
      src!.files.forEach((f, i) => {
        for (const target of f.imports) {
          const rel = target.startsWith(`${src!.root}/`)
            ? target.slice(src!.root.length + 1)
            : null;
          const j = rel === null ? undefined : indexOf.get(rel);
          expect(j, `${p.n}: ${f.path} -> ${target}`).toBeDefined();
          expectedEdges.push([i, j!]);
        }
      });
      expect(p.e).toEqual(expectedEdges);
      // Grid: fixed 70px rows under the 26px header - the box can never clip.
      const rows = Math.ceil(p.m.length / p.b.c);
      expect(p.b.h).toBe(26 + rows * 70);
      expect(rows * p.b.c).toBeGreaterThanOrEqual(p.m.length);
    }
    const pam = data.packages[1];
    const ipam = data.packages[2];
    expect(ipam.b.y).toBe(pam.b.y + pam.b.h + 15);
  });

  it('workflows carry contract operations and resolvable copy', () => {
    expect(data.workflows.map((w) => w.id)).toEqual(WORKFLOWS.map((w) => w.id));
    for (const w of data.workflows) {
      expect(w.title.length, w.id).toBeGreaterThan(0);
      expect(w.subtitle.length, w.id).toBeGreaterThan(0);
      expect(w.steps.length, w.id).toBeGreaterThan(0);
      for (const s of w.steps) {
        expect(specOperationSet.has(s.op), `${w.id}: ${s.op}`).toBe(true);
        expect(s.label.length, `${w.id}: ${s.op}`).toBeGreaterThan(0);
      }
    }
  });

  it('editorial domain grouping references only real tags', () => {
    expect(data.domains.length).toBeGreaterThan(0);
    const names = new Set(data.tags.map((t) => t.n));
    for (const [, csv] of data.domains) {
      for (const tag of csv.split(',')) expect(names.has(tag), tag).toBe(true);
    }
    // every tag is claimed by exactly one editorial domain
    const claimed = data.domains.flatMap(([, csv]) => csv.split(','));
    expect(new Set(claimed).size).toBe(data.tags.length);
  });
});
