import '@testing-library/jest-dom/vitest';

import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// vitest runs without `globals`, so RTL's automatic cleanup never registers
// itself - unmount everything between tests or containers accumulate.
afterEach(() => {
  cleanup();
});
