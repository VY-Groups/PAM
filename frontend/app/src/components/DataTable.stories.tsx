import type { Meta, StoryObj } from '@storybook/react-vite';

import { DataTable } from './DataTable';
import { Value } from './HonestStates';

interface SessionRow {
  id: string;
  host: string;
  user: string;
  protocol: string | null;
}

const columns = [
  { key: 'host', header: 'Host', render: (row: SessionRow) => row.host },
  { key: 'user', header: 'User', render: (row: SessionRow) => row.user },
  {
    key: 'protocol',
    header: 'Protocol',
    render: (row: SessionRow) => <Value value={row.protocol} />,
  },
];

const rows: SessionRow[] = [
  { id: '1', host: 'bastion-01', user: 'alice', protocol: 'ssh' },
  { id: '2', host: 'db-02', user: 'bob', protocol: null },
  { id: '3', host: 'core-03', user: 'carol', protocol: 'rdp' },
];

const meta = {
  title: 'Components/DataTable',
  component: DataTable,
  tags: ['autodocs'],
  args: {
    columns,
    rows,
    rowKey: (row: SessionRow) => row.id,
    caption: 'Privileged sessions',
  },
} satisfies Meta<typeof DataTable<SessionRow>>;

export default meta;
type Story = StoryObj<typeof meta>;

export const WithRows: Story = {};

/** Honest empty state: no fabricated rows (brief §3.2). */
export const Empty: Story = {
  args: { rows: [], emptyMessage: 'No sessions reported' },
};
