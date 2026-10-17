/**
 * System-map extractor for the /topology page (ADR-0013).
 *
 * Reads the committed tree - never a running process - and writes
 * `src/features/topology/topology.generated.ts`. Sources of truth:
 *
 *   1. src/app/layout/nav.ts       sidebar items (path/label/icon/legacy)
 *   2. src/app/router.tsx          the route table and its page components
 *   3. src/api/generated/index.ts  client fn -> (method, contract path)
 *   4. src/features/*              which client functions each feature imports
 *   5. apis/openapi.yaml           the API surface (paths/methods/tags/summaries)
 *   6. pam_master/, backend/phase2_license_server/, backend/ipam_licensing/
 *                                  backend file trees + intra-package imports
 *
 * Output is deterministic (no timestamps) so `pnpm topology` followed by
 * `git diff --exit-code` is a valid drift gate - CI runs exactly that
 * (mirrors the orval step). vitest re-derives sources 1-6 independently
 * in `topology.generated.test.ts`, so this script cannot silently lie.
 *
 * Extraction rules that are policy, not parsing (documented in ADR-0013):
 *   - backend trees exclude tests/ dirs, `test_*` files and conftest.py
 *   - backend edges are strict-python resolutions (absolute or `from .rel`)
 *     against real files only: an edge is shown only if its target exists
 *   - frontend endpoints appear only when the imported client function is
 *     resolved to a real contract operation; unresolved names stay visible
 *     as `clientFunctions` and fail the test layer's completeness check
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import YAML from 'yaml';

const APP = fileURLToPath(new URL('..', import.meta.url)); // .../frontend/app/
const REPO = fileURLToPath(new URL('../../../', import.meta.url)); // repo root
const OUT_FILE = path.join(APP, 'src', 'features', 'topology', 'topology.generated.ts');

const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');
const posix = (p) => p.split(path.sep).join('/');

/* -------------------------------------------------- 1. nav.ts sidebar truth */

function extractNav() {
  const text = read('frontend/app/src/app/layout/nav.ts');
  const items = [];
  // One alternation per object literal, closing brace anchored, so a
  // `danger` flag can never leak in from the neighbouring item. Leading
  // comment lines inside the object (documentation) are allowed for.
  const re =
    /\{\s*(?:\/\/[^\n]*\n\s*)*path: '([^']+)',\s*labelKey: '([^']+)',\s*icon: '([^']+)',\s*(?:legacyHref: '([^']*)',\s*)?(?:danger: true,\s*)?\}/g;
  for (const m of text.matchAll(re)) {
    items.push({
      path: m[1],
      labelKey: m[2],
      icon: m[3],
      legacyHref: m[4] ?? null,
      danger: m[0].includes('danger: true'),
    });
  }
  if (items.length === 0) throw new Error('nav.ts: no NAV_ITEMS parsed');
  return items;
}

/* --------------------------------------------- 2. router.tsx route + pages */

function extractRoutes() {
  const text = read('frontend/app/src/app/router.tsx');
  const routes = [];
  for (const m of text.matchAll(/\{ path: '([^']*)', element: <(\w+) \/> \}/g)) {
    if (!m[1].startsWith('/')) continue; // skips the '*' catch-all
    routes.push({ path: m[1], component: m[2] });
  }
  if (routes.length === 0) throw new Error('router.tsx: no feature routes parsed');
  return routes;
}

/* ------------------------- 3. generated client: fn -> (method, path) pairs */

function extractClientMap() {
  const text = read('frontend/app/src/api/generated/index.ts');
  const marks = [];
  // orval emits three builder bodies (`return \`/p\``, `let url = \`/p\``,
  // query-string variants) - all start with the operation's base path as
  // the first template literal, params as `${camelCase}` placeholders.
  const builderRe = /export const (\w+Url) = \([^)]*\) => \{[\s\S]{0,400}?`([^`]+)`/g;
  const fnRe = /export const (\w+) = async \(/g;
  for (const m of text.matchAll(builderRe)) {
    marks.push({ kind: 'builder', name: m[1], path: m[2], index: m.index });
  }
  for (const m of text.matchAll(fnRe)) {
    marks.push({ kind: 'fn', name: m[1], index: m.index });
  }
  marks.sort((a, b) => a.index - b.index);

  const methodOf = (builderName) => {
    const inner = builderName.replace(/^get/, '').replace(/Url$/, '');
    const m = /^(Get|Post|Put|Patch|Delete)/.exec(inner);
    if (!m) throw new Error(`client: cannot derive method from ${builderName}`);
    return m[1].toUpperCase();
  };

  // `${itemId}` placeholders are orval's camelCase of the contract's
  // `{item_id}` path params - invert the casing for contract comparison.
  // Query-string builders embed `?${stringifiedParams}` in the literal -
  // the contract path stops at the `?`.
  const toContractPath = (url) =>
    url
      .split('?')[0]
      .replace(
        /\$\{(\w+)\}/g,
        (_, name) => `{${name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)}}`,
      );

  const map = new Map(); // name -> { method, path }
  let lastBuilder = null;
  let lastMethod = null;
  for (const mark of marks) {
    if (mark.kind === 'builder') {
      lastBuilder = toContractPath(mark.path);
      lastMethod = methodOf(mark.name);
      map.set(mark.name, { method: lastMethod, path: lastBuilder });
    } else if (lastBuilder) {
      map.set(mark.name, { method: lastMethod, path: lastBuilder });
    }
  }
  if (map.size === 0) throw new Error('generated/index.ts: no client functions parsed');
  return map;
}

/* ------------------------------------------------- 4. feature import truth */

function* walkFiles(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walkFiles(full);
    else yield full;
  }
}

function extractFeatures(clientMap) {
  const featuresDir = path.join(APP, 'src', 'features');
  const features = new Map(); // dir name -> { functions: Set, pageOf: Map<component, file> }
  for (const dir of fs.readdirSync(featuresDir, { withFileTypes: true })) {
    if (!dir.isDirectory()) continue;
    const functions = new Set();
    for (const file of walkFiles(path.join(featuresDir, dir.name))) {
      if (!/\.(ts|tsx)$/.test(file)) continue;
      const text = fs.readFileSync(file, 'utf8');
      const page = /export function (\w+Page)\b/.exec(text);
      if (page) {
        const rec = features.get(dir.name) ?? { functions, pages: new Map() };
        rec.pages.set(page[1], posix(path.relative(REPO, file)));
        features.set(dir.name, rec);
      }
      for (const m of text.matchAll(
        /import\s*\{([^}]*)\}\s*from\s*'([^']*api\/generated)'/g,
      )) {
        for (const raw of m[1].split(',')) {
          const name = raw
            .trim()
            .replace(/^type\s+/, '')
            .split(' as ')[0]
            .trim();
          if (name) functions.add(name);
        }
      }
    }
    const rec = features.get(dir.name);
    if (rec) rec.functions = functions;
    else features.set(dir.name, { functions, pages: new Map() });
  }
  return features;
}

/* ------------------------------------------------- 5. openapi.yaml surface */

function extractApiSurface() {
  const spec = YAML.parse(read('apis/openapi.yaml'));
  const paths = spec.paths ?? {};
  const tags = [];
  const tagIndex = new Map();
  const flat = [];
  const methodCounts = {};
  let operationCount = 0;
  for (const [p, item] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(item)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue;
      const M = method.toUpperCase();
      operationCount += 1;
      methodCounts[M] = (methodCounts[M] ?? 0) + 1;
      flat.push(`${M} ${p}`);
      const tagName = (op.tags ?? ['(none)'])[0];
      let group = tagIndex.get(tagName);
      if (!group) {
        group = { name: tagName, operations: [] };
        tagIndex.set(tagName, group);
        tags.push(group);
      }
      group.operations.push({ method: M, path: p, summary: op.summary ?? null });
    }
  }
  if (operationCount === 0) throw new Error('openapi.yaml: no operations parsed');
  return { pathCount: Object.keys(paths).length, operationCount, methodCounts, tags, flat };
}

/* ------------------------------------------ 6. backend trees and imports */

const BACKEND_ROOTS = [
  { name: 'pam_master', root: 'pam_master' },
  { name: 'phase2_license_server', root: 'backend/phase2_license_server' },
  { name: 'ipam_licensing', root: 'backend/ipam_licensing' },
];

const isTestPath = (rel) =>
  rel
    .split('/')
    .some((seg) => seg === 'tests' || seg === '__pycache__' || seg === '.pytest_cache') ||
  path.posix.basename(rel).startsWith('test_') ||
  path.posix.basename(rel) === 'conftest.py';

/**
 * Resolve one python import reference to a repo-relative file inside the
 * same package root, or null. Strict python semantics: dotted references
 * resolve relative to the importing file's directory, dot-less names from
 * the package root, and the target must be a real file inside the root.
 */
function resolveImport(moduleRef, fromRel, root) {
  const dots = /^[.]+/.exec(moduleRef)?.[0].length ?? 0;
  // Dotted names are directories: `pam_master.keys` -> `pam_master/keys`.
  const rest = moduleRef.slice(dots).split('.').filter(Boolean).join('/');
  let candidate;
  if (dots > 0) {
    let base = path.posix.dirname(fromRel);
    for (let i = 1; i < dots; i += 1) base = path.posix.dirname(base);
    candidate = rest ? path.posix.join(base, rest) : base;
  } else if (rest) {
    // sys.path is the package root (phase2 runs inside its dir, pam_master
    // is run with the outer directory on sys.path).
    candidate = path.posix.join(root, rest);
  } else {
    return null;
  }
  if (candidate !== root && !candidate.startsWith(`${root}/`)) return null; // stays in-package
  for (const file of [`${candidate}.py`, path.posix.join(candidate, '__init__.py')]) {
    if (fs.existsSync(path.join(REPO, file)) && !isTestPath(file)) return file;
  }
  return null;
}

function extractBackend() {
  const packages = [];
  for (const { name, root } of BACKEND_ROOTS) {
    const files = [];
    const seen = new Set();
    for (const file of walkFiles(path.join(REPO, root))) {
      if (!file.endsWith('.py')) continue;
      const rel = posix(path.relative(REPO, file));
      if (isTestPath(rel)) continue;
      const relInRoot = posix(path.relative(root, rel));
      if (seen.has(relInRoot)) continue;
      seen.add(relInRoot);
      const text = fs.readFileSync(file, 'utf8');
      const imports = new Set();
      const re =
        /^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import(?:[ \t]+\(?([\w., ]*))?|import[ \t]+([.\w]+))/gm;
      for (const m of text.matchAll(re)) {
        if (m[1] !== undefined) {
          const ref = m[1];
          const names = (m[2] ?? '')
            .split(',')
            .map((n) => n.trim())
            .filter(Boolean);
          const add = (target) => {
            const resolved = resolveImport(target, rel, root);
            if (resolved && resolved !== rel) {
              imports.add(resolved);
              return true;
            }
            return false;
          };
          if (ref.replace(/^[.]+/, '') === '') {
            // `from . import name` - the names are submodules.
            for (const nm of names) add(`${ref}${nm}`);
          } else {
            // `from pkg import a, b`: a/b are submodules when they exist
            // as files (crypto, db, registry); otherwise they are symbols
            // and the dependency is the imported module itself.
            let added = false;
            for (const nm of names) if (add(`${ref}.${nm}`)) added = true;
            if (!added) add(ref);
          }
        } else {
          const resolved = resolveImport(m[3], rel, root);
          if (resolved && resolved !== rel) imports.add(resolved);
        }
      }
      files.push({
        path: relInRoot,
        lines: text.split('\n').length,
        imports: [...imports].sort(),
      });
    }
    if (files.length === 0) throw new Error(`backend root ${root}: no python files parsed`);
    files.sort((a, b) => a.path.localeCompare(b.path));
    packages.push({ name, root: posix(root), files });
  }
  return packages;
}

/* ------------------------------------------------------------- assemble */

const nav = extractNav();
const routes = extractRoutes();
const clientMap = extractClientMap();
const features = extractFeatures(clientMap);
const api = extractApiSurface();
const backend = extractBackend();

const componentFeature = new Map();
for (const [dir, rec] of features) {
  for (const component of rec.pages.keys()) componentFeature.set(component, dir);
}

const API_OPERATIONS = api.flat;
const opSet = new Set(API_OPERATIONS);

const resolve = (fnName) => {
  const hit = clientMap.get(fnName);
  if (!hit) return null;
  const op = `${hit.method} ${hit.path}`;
  // Every resolved endpoint must be a real contract operation - a naming
  // or pairing mistake in this script fails loudly, never renders.
  if (!opSet.has(op))
    throw new Error(`client fn ${fnName} resolved to "${op}", not in openapi.yaml`);
  return op;
};

/** Distinct resolved contract operations of one feature (sorted). */
const featureEndpoints = (feature) => {
  if (!feature) return [];
  const names = [...(features.get(feature)?.functions ?? [])];
  return [...new Set(names.map(resolve).filter((x) => x !== null))].sort();
};

const frontend = [];
for (const item of nav) {
  const route = routes.find((r) => r.path === item.path) ?? null;
  const feature = route ? (componentFeature.get(route.component) ?? null) : null;
  const functions = feature ? [...(features.get(feature)?.functions ?? [])].sort() : [];
  frontend.push({
    path: item.path,
    labelKey: item.labelKey,
    icon: item.icon,
    legacyHref: item.legacyHref,
    danger: item.danger,
    state: route ? 'live' : 'pending',
    component: route?.component ?? null,
    feature,
    clientFunctions: functions,
    endpoints: featureEndpoints(feature),
  });
}
// Routes that are not sidebar items (login, ...) still belong to the map.
for (const route of routes) {
  if (frontend.some((f) => f.path === route.path)) continue;
  const feature = componentFeature.get(route.component) ?? null;
  const functions = feature ? [...(features.get(feature)?.functions ?? [])].sort() : [];
  frontend.push({
    path: route.path,
    labelKey: null,
    icon: null,
    legacyHref: null,
    danger: false,
    state: 'live',
    component: route.component,
    feature,
    clientFunctions: functions,
    endpoints: featureEndpoints(feature),
  });
}

// Names the features import from the generated module that are not
// fetchers (response/param types). Reported, never silently dropped.
const unresolved = [];
for (const [dir, rec] of features) {
  for (const fn of rec.functions) if (!clientMap.has(fn)) unresolved.push(`${dir}: ${fn}`);
}

const backendOut = backend.map((pkg) => ({
  name: pkg.name,
  root: pkg.root,
  files: pkg.files,
}));

/* ----------------------------------------------------------------- emit */

const header = `/**
 * AUTO-GENERATED by \`pnpm topology\` (scripts/topology.mjs) - never
 * hand-edited. Deterministic output: regenerate + \`git diff --exit-code\`
 * is the CI drift gate; vitest re-parses every source independently and
 * fails on mismatch (ADR-0013). Sources: nav.ts, router.tsx, the orval
 * client, src/features/* imports, apis/openapi.yaml, backend trees.
 */
`;

const typeBlock = `/** One sidebar/route row: nav truth joined with route-table truth. */
export interface FrontendRouteView {
  path: string;
  labelKey: string | null;
  icon: string | null;
  legacyHref: string | null;
  danger: boolean;
  state: 'live' | 'pending';
  component: string | null;
  feature: string | null;
  clientFunctions: string[];
  endpoints: string[];
}

/** One python file of a backend package: size and intra-package imports. */
export interface BackendFileView {
  path: string;
  lines: number;
  imports: string[];
}

export interface BackendPackageView {
  name: string;
  root: string;
  files: BackendFileView[];
}

/** One operation of the contract, grouped by its first OpenAPI tag. */
export interface ApiOperationView {
  method: string;
  path: string;
  summary: string | null;
}

export interface ApiTagView {
  name: string;
  operations: ApiOperationView[];
}
`;

const out = `${header}${typeBlock}
export const FRONTEND_ROUTES: FrontendRouteView[] = ${JSON.stringify(frontend, null, 2)};

export const BACKEND_PACKAGES: BackendPackageView[] = ${JSON.stringify(backendOut, null, 2)};

export const API_TAGS: ApiTagView[] = ${JSON.stringify(api.tags, null, 2)};

export const API_METHOD_COUNTS: Record<string, number> = ${JSON.stringify(api.methodCounts, null, 2)};

export const API_PATH_COUNT = ${api.pathCount};

export const API_OPERATION_COUNT = ${api.operationCount};

/** Every operation as "METHOD /path" - the workflow contract-check set. */
export const API_OPERATIONS: string[] = ${JSON.stringify(API_OPERATIONS, null, 2)};

/** The exact source files this module was extracted from (rendered as provenance). */
export const SOURCE_FILES: string[] = ${JSON.stringify(
  [
    'frontend/app/src/app/layout/nav.ts',
    'frontend/app/src/app/router.tsx',
    'frontend/app/src/api/generated/index.ts',
    'frontend/app/src/features/*',
    'apis/openapi.yaml',
    'pam_master/**/*.py',
    'backend/phase2_license_server/**/*.py',
    'backend/ipam_licensing/**/*.py',
  ],
  null,
  2,
)};
`;

fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
fs.writeFileSync(OUT_FILE, out, 'utf8');
console.log(
  `topology: wrote ${path.relative(REPO, OUT_FILE)} ` +
    `(${frontend.length} routes, ${backendOut.length} backend packages, ` +
    `${api.operationCount} operations across ${api.tags.length} tags)`,
);

/* -------------------------------------------------- mermaid doc emission */

/**
 * The same extracted data, rendered as Mermaid diagrams under
 * docs/architecture/ (the user-asked-for artifact): GitHub renders the
 * blocks directly, and the docs share the extractor's drift gate - CI
 * regenerates and fails on any diff. Every emission parses its own
 * section's structure from the real source files (queries.ts hooks,
 * NetworkSection cards, workflows.ts steps, en.json labels) and throws
 * loudly when a pattern no longer matches, so a doc can never describe
 * something the code does not say.
 */
const DOC_DIR = path.join(REPO, 'docs', 'architecture');
const i18nCatalog = JSON.parse(read('frontend/app/src/i18n/en.json'));

/** Resolve a dotted i18n key against the real catalogue (ADR-0010). */
function i18nGet(key) {
  const value = key
    .split('.')
    .reduce((acc, part) => (acc == null ? undefined : acc[part]), i18nCatalog);
  if (typeof value !== 'string') throw new Error(`i18n: missing key "${key}"`);
  return value;
}

/** Mermaid-safe quoted label: no double quote ever reaches the renderer. */
const q = (s) => `"${String(s).replace(/"/g, "'")}"`;

function docHeader(title, sources) {
  return [
    '<!--',
    'AUTO-GENERATED by `pnpm topology` (frontend/app/scripts/topology.mjs)',
    'for ADR-0013 - never hand-edited. Regenerate + `git diff --exit-code`',
    'is the CI drift gate; every figure below is extracted from:',
    ...sources.map((s) => `  - ${s}`),
    '-->',
    '',
    `# ${title}`,
    '',
  ].join('\n');
}

function writeDoc(name, markdown) {
  const file = path.join(DOC_DIR, name);
  fs.mkdirSync(DOC_DIR, { recursive: true });
  fs.writeFileSync(file, markdown, 'utf8');
  console.log(`topology: wrote ${posix(path.relative(REPO, file))}`);
}

function writeFrontendMapDoc() {
  const live = frontend.filter((r) => r.state === 'live');
  const pending = frontend.filter((r) => r.state === 'pending');
  const routeId = new Map(frontend.map((r, i) => [r.path, `r${i}`]));
  const endpointId = new Map();
  const body = ['flowchart TD'];
  body.push('  subgraph s_live["Implemented in the React shell"]');
  for (const r of live) {
    const name = r.labelKey
      ? `${r.path} - ${i18nGet(r.labelKey)}`
      : `${r.path} (${r.component})`;
    body.push(`  ${routeId.get(r.path)}[${q(name)}]`);
  }
  body.push('  end');
  if (pending.length > 0) {
    body.push(
      '  subgraph s_pending["F4 pending - the legacy screen stays served (ADR-0012)"]',
    );
    for (const r of pending) {
      body.push(`  ${routeId.get(r.path)}[${q(`${r.path} - ${i18nGet(r.labelKey)}`)}]`);
    }
    body.push('  end');
  }
  for (const r of live) {
    for (const ep of r.endpoints) {
      if (!endpointId.has(ep)) {
        endpointId.set(ep, `e${endpointId.size}`);
        body.push(`  ${endpointId.get(ep)}[${q(ep)}]`);
      }
      body.push(`  ${routeId.get(r.path)} --> ${endpointId.get(ep)}`);
    }
  }
  for (const r of pending) {
    body.push(
      `  ${routeId.get(r.path)} -.-> ${routeId.get(r.path)}l[${q(`legacy: ${r.legacyHref}`)}]`,
    );
  }
  if (pending.length > 0) {
    body.push('  classDef pending fill:#fde68a,stroke:#92400e');
    body.push(`  class ${pending.map((r) => routeId.get(r.path)).join(',')} pending`);
  }
  const md =
    docHeader('Frontend route map', [
      'frontend/app/src/app/layout/nav.ts',
      'frontend/app/src/app/router.tsx',
      'frontend/app/src/api/generated/index.ts (client fn -> contract operation)',
      'frontend/app/src/features/* (which client functions each feature imports)',
      'apis/openapi.yaml',
    ]) +
    `${frontend.length} console routes (${nav.length} sidebar items + ${frontend.length - nav.length} non-sidebar) ` +
    'joined with the contract operations their generated-client calls resolve to.\n\n' +
    '```mermaid\n' +
    body.join('\n') +
    '\n```\n';
  writeDoc('frontend-map.md', md);
}

function writeBackendMapDoc() {
  const fileId = new Map();
  const body = ['flowchart TD'];
  backendOut.forEach((pkg, p) => {
    body.push(`  subgraph p${p} ${q(`${pkg.name} (${pkg.root})`)}`);
    pkg.files.forEach((f, i) => {
      fileId.set(`${pkg.root}/${f.path}`, `b${p}_${i}`);
      body.push(`  b${p}_${i}[${q(`${f.path} - ${f.lines} lines`)}]`);
    });
    body.push('  end');
  });
  for (const pkg of backendOut) {
    for (const f of pkg.files) {
      const from = fileId.get(`${pkg.root}/${f.path}`);
      for (const target of f.imports) {
        const to = fileId.get(target);
        if (!to) throw new Error(`backend map: unresolved import target ${target}`);
        body.push(`  ${from} --> ${to}`);
      }
    }
  }
  const edgeCount = backendOut.reduce(
    (n, pkg) => n + pkg.files.reduce((m, f) => m + f.imports.length, 0),
    0,
  );
  const md =
    docHeader('Backend package map', [
      'pam_master/**/*.py (tests, test_* and conftest.py excluded)',
      'backend/phase2_license_server/**/*.py (same policy)',
      'backend/ipam_licensing/**/*.py (same policy)',
      'python import statements resolved strictly to files that exist',
    ]) +
    `${backendOut.length} packages, ${backendOut.reduce((n, p) => n + p.files.length, 0)} modules, ` +
    `${edgeCount} drawn intra-package import edges.\n\n` +
    '```mermaid\n' +
    body.join('\n') +
    '\n```\n';
  writeDoc('backend-map.md', md);
}

function writeApiSurfaceDoc() {
  const body = ['flowchart LR'];
  api.tags.forEach((tag, t) => {
    body.push(`  subgraph t${t} ${q(`${tag.name} - ${tag.operations.length} operations`)}`);
    tag.operations.forEach((op, i) => {
      body.push(`  o${t}_${i}[${q(`${op.method} ${op.path}`)}]`);
    });
    body.push('  end');
  });
  const methods = Object.entries(api.methodCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([m, n]) => `${m} ${n}`)
    .join(', ');
  const md =
    docHeader('API surface (contract)', ['apis/openapi.yaml']) +
    `${api.pathCount} paths / ${api.operationCount} operations across ${api.tags.length} tags ` +
    `(${methods}); grouped by each operation's first OpenAPI tag.\n\n` +
    '```mermaid\n' +
    body.join('\n') +
    '\n```\n';
  writeDoc('api-surface.md', md);
}

/** Hook -> client fn (queries.ts) and card -> hook (NetworkSection.tsx). */
function extractNetworkWiring() {
  const qtext = read('frontend/app/src/features/topology/queries.ts');
  const hookToFn = new Map();
  for (const m of qtext.matchAll(
    /export function (use\w+)\(\)[\s\S]{0,400}?expectOk\(await (\w+)\(\)/g,
  )) {
    hookToFn.set(m[1], m[2]);
  }
  if (hookToFn.size === 0) throw new Error('queries.ts: no live hooks parsed');
  const ns = read('frontend/app/src/features/topology/NetworkSection.tsx');
  const cards = [];
  for (const m of ns.matchAll(
    /function (\w+Card)\(\) \{[\s\S]{0,240}?const \w+ = (use\w+)\(\);/g,
  )) {
    const component = m[1];
    const hook = m[2];
    const fn = hookToFn.get(hook);
    if (!fn) throw new Error(`NetworkSection: ${component} calls unparsed hook ${hook}`);
    if (!clientMap.has(fn))
      throw new Error(`NetworkSection: ${component} uses unknown ${fn}`);
    const kind = component.replace(/Card$/, '').toLowerCase();
    cards.push({
      hook,
      endpoint: resolve(fn),
      title: i18nGet(`topology.network.${kind}Title`),
    });
  }
  if (cards.length === 0) throw new Error('NetworkSection: no cards parsed');
  return cards;
}

function writeNetworkPostureDoc() {
  const cards = extractNetworkWiring();
  const body = ['flowchart LR'];
  cards.forEach((c, i) => {
    body.push(`  n${i}[${q(c.endpoint)}]`);
    body.push(`  c${i}[${q(c.title)}]`);
    body.push(`  n${i} -->|${c.hook}| c${i}`);
  });
  const md =
    docHeader('Network posture wiring (live)', [
      'frontend/app/src/features/topology/queries.ts (hook -> client fn)',
      'frontend/app/src/features/topology/NetworkSection.tsx (card -> hook)',
      'frontend/app/src/api/generated/index.ts',
      'apis/openapi.yaml',
    ]) +
    'The Network view of `/topology` fetches these endpoints live through ' +
    'the generated client (`expectOk`) and renders one honest card per ' +
    'answer (loading / not-connected / verbatim data). This document shows ' +
    'the wiring; the values come from the running node.\n\n' +
    '```mermaid\n' +
    body.join('\n') +
    '\n```\n';
  writeDoc('network-posture.md', md);
}

/** workflows.ts is parsed structurally; evidence consts are resolved. */
function extractWorkflowFlows() {
  const text = read('frontend/app/src/features/topology/workflows.ts');
  const consts = new Map();
  for (const m of text.matchAll(/^const (\w+) = '([^']+)';$/gm)) consts.set(m[1], m[2]);
  const flows = [];
  const flowRe =
    /\{\s*id: '(\w+)',\s*titleKey: '([^']+)',\s*subtitleKey: '([^']+)',\s*steps: \[([\s\S]*?)\n {4}\],\n {2}\},/g;
  for (const m of text.matchAll(flowRe)) {
    const steps = [];
    const stepRe =
      /operation: '([^']+)',\s*labelKey: '([^']+)',(?:\s*noteKey: '([^']+)',)?\s*evidence: \{\s*file: (?:'([^']+)'|(\w+)),\s*contains: '((?:[^'\\]|\\.)*)',?\s*\},/g;
    for (const s of m[4].matchAll(stepRe)) {
      const file = s[4] ?? consts.get(s[5]);
      if (!file) throw new Error(`workflows.ts: unknown evidence const ${s[5]}`);
      steps.push({
        operation: s[1],
        labelKey: s[2],
        noteKey: s[3] ?? null,
        file,
        contains: s[6],
      });
    }
    if (steps.length === 0)
      throw new Error(`workflows.ts: workflow ${m[1]} parsed 0 steps`);
    flows.push({ id: m[1], titleKey: m[2], subtitleKey: m[3], steps });
  }
  if (flows.length === 0) throw new Error('workflows.ts: no workflows parsed');
  return flows;
}

function writeWorkflowsDoc() {
  const flows = extractWorkflowFlows();
  const parts = [
    docHeader('Application workflows (contract-true)', [
      'frontend/app/src/features/topology/workflows.ts',
      'frontend/app/src/i18n/en.json (step labels)',
      'apis/openapi.yaml (every arrow is an operation of the contract)',
      'the named proof files (fixture captures, tests, standing gate)',
    ]) +
      'Five curated lifecycles: every arrow is a real contract operation ' +
      'and every note names the repo proof that drives the step (verbatim ' +
      'fixture capture, test, or standing gate).\n',
  ];
  for (const flow of flows) {
    parts.push(`## ${i18nGet(flow.titleKey)}\n`);
    parts.push(`${i18nGet(flow.subtitleKey)}\n`);
    const body = [
      'sequenceDiagram',
      '  autonumber',
      '  participant UI as Console',
      '  participant API as PAM API (contract)',
    ];
    for (const step of flow.steps) {
      body.push(`  UI->>API: ${step.operation}`);
      body.push(`  Note over UI,API: ${i18nGet(step.labelKey)}`);
      if (step.noteKey) body.push(`  Note over UI,API: ${i18nGet(step.noteKey)}`);
      body.push(
        `  Note over UI,API: ${i18nGet('topology.workflows.evidence')}: ${step.file} :: ${step.contains}`,
      );
    }
    parts.push('```mermaid\n' + body.join('\n') + '\n```\n');
  }
  writeDoc('workflows.md', parts.join('\n'));
}

writeFrontendMapDoc();
writeBackendMapDoc();
writeApiSurfaceDoc();
writeNetworkPostureDoc();
writeWorkflowsDoc();

if (unresolved.length > 0) {
  console.log(
    `topology: non-fetch imports of the generated client (types, reported only):`,
  );
  for (const entry of unresolved.sort()) console.log(`  - ${entry}`);
}
