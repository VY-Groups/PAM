import type { Preview } from '@storybook/react-vite';

// Stories render with the real design system: generated tokens (Tailwind 4),
// bundled fonts and the icon class - same pipeline as the app (ADR-0002/0007).
import '../src/styles/tokens.css';
import '../src/styles/icons.css';
import '@fontsource-variable/geist';
import '@fontsource/jetbrains-mono';
import '@fontsource/material-symbols-outlined/latin-400.css';

const preview: Preview = {
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date/i,
      },
    },

    a11y: {
      // Interactive dev aid: violations show in the panel but do not fail
      // tests. The CI-enforced axe check runs per component in Vitest
      // (jsdom, color-contrast excluded - see src/test/axe.ts, ADR-0008).
      test: 'todo',
    },
  },
};

export default preview;
