import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// ADR-0007: fonts are bundled, never CDN (air-gapped customers).
import '@fontsource-variable/geist';
import '@fontsource/jetbrains-mono';

// ADR-0002: the single tokens file (generated from the as-built config).
import './styles/tokens.css';

import { App } from './App';

const container = document.getElementById('root');
if (!container) throw new Error('#root missing from index.html');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
