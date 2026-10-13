import type { ReactNode } from 'react';

export interface DataTableColumn<T> {
  key: string;
  header: string;
  /** Cell renderer; return the honest `Value` component for absent data. */
  render: (row: T) => ReactNode;
}

export interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  /** Stable row key. */
  rowKey: (row: T) => string;
  /** Accessible name for the table (axe requires one on data tables). */
  caption: string;
  /** Rendered when rows is empty - honest state, never sample data. */
  emptyMessage?: ReactNode;
  className?: string;
}

/**
 * Table (brief §2): header row font-label-badge uppercase text-outline,
 * rows body-sm, zebra via bg-surface-container-low/40, actions as icon buttons
 * (provided by the column render function).
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  emptyMessage,
  className = '',
}: DataTableProps<T>) {
  return (
    <table className={`w-full border-collapse ${className}`}>
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr className="border-b border-outline-variant">
          {columns.map((col) => (
            <th
              key={col.key}
              scope="col"
              className="text-left font-label-badge text-label-badge uppercase text-outline py-space-sm px-space-md"
            >
              {col.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.length === 0 ? (
          <tr>
            <td
              colSpan={columns.length}
              className="text-center font-body-sm text-body-sm text-on-surface-variant py-space-lg px-space-md"
            >
              {emptyMessage ?? '—'}
            </td>
          </tr>
        ) : (
          rows.map((row, index) => (
            <tr
              key={rowKey(row)}
              className={`font-body-sm text-body-sm text-on-surface ${index % 2 === 1 ? 'bg-surface-container-low/40' : ''}`}
            >
              {columns.map((col) => (
                <td key={col.key} className="py-space-sm px-space-md">
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))
        )}
      </tbody>
    </table>
  );
}
