/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// ADR-0012: served under /app/ during the strangler migration; the basename
// collapses to / at F5. Build output is fully offline (fonts bundled, no CDN).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { storybookTest } from '@storybook/addon-vitest/vitest-plugin';
import { playwright } from '@vitest/browser-playwright';
const dirname = path.dirname(fileURLToPath(import.meta.url));

// More info at: https://storybook.js.org/docs/next/writing-tests/integrations/vitest-addon
export default defineConfig({
  base: '/app/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  // Dev parity with the deployed shape (ADR-0012): the app is same-origin
  // with the license server, so `pnpm dev` proxies the API to the local rig.
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:5000',
      '/health': 'http://127.0.0.1:5000',
    },
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          // The name makes this project selectable on its own
          // (`vitest run --project=console`): under Storybook 10.6.2 the
          // browser project's Vite server and this project's files compete
          // for the same CPU in one invocation, and the browser project's
          // orchestrator then loses its port race (ERR_CONNECTION_REFUSED
          // on /__vitest_test__/). The two projects run as two invocations
          // instead, the browser one first because it needs the machine to
          // itself - see the "test" script.
          name: 'console',
          environment: 'jsdom',
          setupFiles: './src/test/setup.ts',
          css: false,
          // Full-suite runs contend with per-file jsdom setup on this
          // constrained machine (the suite's own hint: ~6 s of env creation
          // per file); the default 5 s hang guard started flaking the JIT
          // screen's first test once screen 5 joined the suite. The window
          // moved again with the Storybook 10.6.2 / vitest 5.0.5 bump: the
          // first run of a fresh checkout also pays Vite's dependency
          // optimization, and the files that wait for it exceeded 10 s
          // (cold local run: 15 files, all of them the guard, no
          // assertion change). Content assertions are unchanged - only the
          // guard window.
          testTimeout: 20_000,
        },
      },
      {
        extends: true,
        plugins: [
          // The plugin will run tests for the stories defined in your Storybook config
          // See options at: https://storybook.js.org/docs/next/writing-tests/integrations/vitest-addon#storybooktest
          storybookTest({
            configDir: path.join(dirname, '.storybook'),
          }),
        ],
        test: {
          name: 'storybook',
          browser: {
            enabled: true,
            headless: true,
            provider: playwright({}),
            instances: [
              {
                browser: 'chromium',
              },
            ],
          },
        },
      },
    ],
  },
});
