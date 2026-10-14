/**
 * Ledger-export CSV helpers for the Compliance screen (F4 screen 6).
 * Pure functions in their own module so the export path is unit-testable
 * and the page stays a component-only module (react-refresh rule).
 */

/** One ledger row of the NDJSON export (contract: seq, event_ref, hashes). */
export interface LedgerRecord {
  seq: number;
  created_at: string;
  source: string;
  action: string;
  actor: string;
  subject: string;
  detail?: Record<string, unknown>;
  event_ref?: string;
  prev_hash: string;
  event_hash: string;
}

/**
 * Build the auditor CSV from the raw NDJSON records (same columns the
 * legacy console exported: chain position, provenance and both hashes
 * per row).
 */
export function buildAuditCsv(records: LedgerRecord[]): string {
  const rows: string[][] = [
    [
      'seq',
      'created_at',
      'source',
      'action',
      'actor',
      'subject',
      'detail',
      'event_ref',
      'prev_hash',
      'event_hash',
    ],
  ];
  for (const r of records) {
    rows.push([
      String(r.seq),
      r.created_at,
      r.source,
      r.action,
      r.actor,
      r.subject,
      JSON.stringify(r.detail ?? {}),
      r.event_ref ?? '',
      r.prev_hash,
      r.event_hash,
    ]);
  }
  return rows
    .map((row) =>
      row.map((v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v)).join(','),
    )
    .join('\n');
}

/** Parse the server's NDJSON body; throws on a malformed line (honest). */
export function parseNdjson(text: string): LedgerRecord[] {
  return text
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line) as LedgerRecord);
}
