import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

import i18n from '../../i18n';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * App-level crash guard (plan §3 `app/error/`): a render error shows an
 * honest message and a retry instead of a white screen. Message comes from
 * the i18n catalogue (ADR-0010); the class component cannot use hooks, so
 * it reads the initialised instance directly.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Console only - never POST the error anywhere (plan §6).
    console.error('VY-PAM console render error', error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div
          role="alert"
          className="max-w-xl mx-auto mt-space-xl flex flex-col gap-space-md p-space-xl rounded-xl bg-surface-container-lowest border border-outline-variant/30"
        >
          <h1 className="font-headline-lg text-headline-lg text-on-surface">
            {i18n.t('errors.unexpectedTitle')}
          </h1>
          <p className="font-body-md text-body-md text-on-surface-variant">
            {i18n.t('errors.unexpectedBody')}
          </p>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="self-start px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-label-md text-label-md shadow-sm"
          >
            {i18n.t('errors.retry')}
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
