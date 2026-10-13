/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// ADR-0012: served under /app/ during the strangler migration; the basename
// collapses to / at F5. Build output is fully offline (fonts bundled, no CDN).
export default defineConfig({
  base: '/app/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: false,
  },
});
