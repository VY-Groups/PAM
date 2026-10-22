import '@testing-library/jest-dom/vitest';

import { cleanup, configure } from '@testing-library/react';
import { afterEach } from 'vitest';

// vitest runs without `globals`, so RTL's automatic cleanup never registers
// itself - unmount everything between tests or containers accumulate.
afterEach(() => {
  cleanup();
});

// The same guard-window move as vite.config.ts's testTimeout: a findBy*
// query waits 1 s by default, and under the suite's load a data-driven
// screen can need longer to render its first row (the Security screen's
// factor row was the one that fell behind). Content assertions are
// unchanged - only the wait window.
configure({ asyncUtilTimeout: 5_000 });
