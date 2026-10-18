import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoAxeViolations } from '../test/axe';
import { DataTable } from './DataTable';
import { Value } from './HonestStates';

interface Row {
  id: string;
  host: string;
  protocol: string | null;
}

const columns = [
  { key: 'host', header: 'Host', render: (row: Row) => row.host },
  {
    key: 'protocol',
    header: 'Protocol',
    render: (row: Row) => <Value value={row.protocol} />,
  },
];

const rows: Row[] = [
  { id: '1', host: 'bastion-01', protocol: 'ssh' },
  { id: '2', host: 'db-02', protocol: null },
];

describe('DataTable', () => {
  it('renders headers in uppercase label-badge style (brief §2)', () => {
    render(
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} caption="Sessions" />,
    );
    const header = screen.getByRole('columnheader', { name: 'Host' });
    expect(header.className).toContain('font-label-badge');
    expect(header).toHaveAttribute('scope', 'col');
  });

  it('renders rows with body-sm classes', () => {
    render(
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} caption="Sessions" />,
    );
    expect(screen.getByText('bastion-01').closest('tr')!.className).toContain(
      'font-body-sm',
    );
  });

  it('zebra-stripes odd rows (index 1) per brief §2', () => {
    const { container } = render(
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} caption="Sessions" />,
    );
    const trs = container.querySelectorAll('tbody tr');
    expect(trs[1].className).toContain('bg-surface-container-low/40');
    expect(trs[0].className).not.toContain('bg-surface-container-low/40');
  });

  it('shows the honest em-dash cell for absent data (brief §3.2)', () => {
    render(
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} caption="Sessions" />,
    );
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('shows the empty state instead of sample rows (brief §3.2)', () => {
    render(
      <DataTable
        columns={columns}
        rows={[]}
        rowKey={(r) => r.id}
        caption="Sessions"
        emptyMessage="No sessions reported"
      />,
    );
    expect(screen.getByText('No sessions reported')).toBeInTheDocument();
    expect(screen.queryByText('bastion-01')).not.toBeInTheDocument();
  });

  it('puts bodyDataRole on the tbody (settings cluster tables)', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        rows={[]}
        rowKey={(r) => r.id}
        caption="Sessions"
        bodyDataRole="cluster-rows"
        emptyMessage="No sessions reported"
      />,
    );
    expect(container.querySelector('tbody[data-role="cluster-rows"]')).not.toBeNull();
  });

  it('has no axe violations (with rows)', async () => {
    const { container } = render(
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} caption="Sessions" />,
    );
    await expectNoAxeViolations(container);
  });

  it('has no axe violations (empty state)', async () => {
    const { container } = render(
      <DataTable columns={columns} rows={[]} rowKey={(r) => r.id} caption="Sessions" />,
    );
    await expectNoAxeViolations(container);
  });
});
