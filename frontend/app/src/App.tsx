/**
 * F1 foundations page - shows the design tokens resolve (Tailwind compiled
 * from tokens.css, fonts bundled). Screens arrive F3/F4; this is the honest
 * scaffold state: no fabricated data anywhere.
 */
export function App() {
  return (
    <main className="min-h-screen bg-background p-margin-lg">
      <header className="border-b border-outline-variant/30 pb-space-lg">
        <h1 className="font-headline-lg text-headline-lg text-on-surface">
          VY-<span className="text-primary">PAM</span> Console
        </h1>
        <p className="font-body-md text-body-md text-on-surface-variant">
          Frontend rebuild - F1 foundations
        </p>
      </header>
      <section aria-label="Design tokens" className="mt-space-xl">
        <h2 className="font-headline-sm text-headline-sm text-on-surface">Tokens</h2>
        <p className="font-code-sm text-code-sm text-on-surface-variant">
          generated from the as-built config - see docs/frontend/ADR-0002-styling.md
        </p>
      </section>
    </main>
  );
}
