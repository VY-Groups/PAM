import { defineConfig } from 'orval';

// ADR-0004: orval reads the repo-root contract and generates the typed
// client into src/api/generated/. Generated code is never hand-edited;
// CI regenerates and fails on drift.
export default defineConfig({
  vypam: {
    input: {
      target: '../../apis/openapi.yaml',
    },
    output: {
      target: './src/api/generated/index.ts',
      schemas: './src/api/generated/models',
      client: 'fetch',
      clean: true,
      override: {
        // The shared http wrapper (base URL, auth, timeout, error shape,
        // backend-down detection) - plan §3 api/http.ts.
        mutator: './src/api/http.ts',
      },
    },
  },
});
