// Live-screens honesty sweep (README: the scan for legacy fake strings).
// Every API-driven screen must show no fabricated design values in either
// load mode: HTTP fills real data from the API, file:// stays honest static.
// Exit code 1 on any failed assertion.
import { chromium } from 'playwright-core';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHOTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(SHOTS_DIR); // shots_tool -> repo root
const BASE = process.env.BASE || 'http://127.0.0.1:5000';

const SCREENS = [
  'pam_command_center_threat_dashboard',
  'credential_vault_secrets_inventory',
  'compliance_soc_2_audit_center',
  'target_infrastructure_connectors',
  'jit_access_ephemeral_approvals',
  'live_session_recording_inspection_hub',
  'policy_zero_trust_rules_engine',
  'break_glass_emergency_protocol',
  'vendor_access_third_party_lifecycle',
];

const FORBIDDEN = [
  // shared chrome (purged suite-wide)
  'us-east-prod-cluster', 'Global Zone', 'SOC2 Type II', '120 evt/s',
  'Alex Mercer', 'Enterprise SecOps Lead', 'Zero Standing Privileges',
  // legacy discovery design values
  '2,875', '482 mTLS', '18 Unmanaged', '2,857', '1,420',
  'INGRESS SHIELD ACTIVE', 'v4.8.2', '10.140.0.0/16', '14 minutes ago',
  '+3 Ephemeral', 'ALL REGIONS ACTIVE', 'POLLING INTERVAL',
  '18 Connectors Active', 'Zero-Trust Gateway', '0 standing admin',
  'Session TLS 1.3', 'Audit Digest Verified', 'SYN_SENT', 'HEARTBEAT',
  'mTLS handshake', 'env:production', 'Zero-Touch', 'TLS 1.3 Strict',
  'Requires PAM Vault Ingestion', 'connector-east', 'k8s-prod',
  'Scanning CIDR', 'HIGH LOAD', 'Equinix', 'POLICY_VIOLATION',
  'US-East Gateway', 'EU-Central', 'Hybrid On-Prem', 'TCP_ESTABLISHED',
  // legacy generic fabrications ('Standing Privileges' stays allowed: on the
  // command center it is an honest descriptor label with a static — value)
  '12ms', '99.98', 'Optimal', 'Degraded (0)', 'Enforced (',
  // frozen discovery/vault pagination pairs (honest live pagination renders
  // real counts, so only the fabricated *pairs* are forbidden)
  'Showing 5 of 2,875', 'Showing 6 of 4,892', '7.8ms',
  // JIT (4b) design values, purged at runtime by the live wiring
  '41m remaining', '2 High Urgency', 'Marcus Brody', 'JIRA-5920',
  'Live Synced', 'Strict_RECORDING', 'AssumeRole', '94.1',
  // live session hub (4c) design values, purged at runtime by the wiring
  'PAM-9042', 'PAM-9043', 'PAM-9044', 'r.vance', 'a.patel', 'j.doe',
  'prod-payment-gateway-01', 'ad-domain-controller-01',
  'k8s-billing-api-pod-3', 'Sarah Chen', 'Automated Sentinel Bot',
  'INC-9938', 'PAM-Guard-v4.2', '1 HIGH RISK SESSION',
  'AIR-GAPPED AUDIT ACTIVE', '/ 40 Quota', 'Live Streams (14)',
  'cat /etc/shadow', 'AEGIS SENTINEL', 'kernel hook', 'RISK 84',
  '46m remaining', '2 / 2 Verified', '15:18:00', 'EXIT 0',
  'ACTIVE TYPING', 'Dual-Control Observers', 'Keystroke Biometric',
  'Mirror Digest', 'root@prod-payment', 'pts/2', 'FPS: 30',
  'Real-time terminal', 'Join Dual-Control', 'Revoke User Bastion',
  'Freeze Stream', 'SIGKILL', 'SHA-256 Frame Digest', '00:14:28',
  'Threat & Anomaly Panel', 'Dual-Control Supervision', '14ms',
  'Terminate & Revoke Credentials', 'Recommended SecOps', 'Anomaly Flag',
  'VXLAN segment', 'tunneling beacon', 'sudo -i', 'root@payment',
  'Mirroring Live', 'Nodes connected',
  // policy zero-trust rules engine (4d) design values, purged at runtime by
  // the wiring ('Zero-Standing Privilege' stays allowed: honest label elsewhere)
  'prod-mesh-01', 'Dual-approver workflow ready', 'Synced 2h ago',
  'secops-ci', 'v4.18.2-prod', '9b2d87e', 'Verified Signatures',
  'Rule #SEC-094', 'Match #SEC-094', 'QRM-022', 'POS-104',
  'Block Destructive System Commands', '14 blocks this week',
  'Deterministic POSIX ERE', 'env:prod*', 'Edit Syntax', 'Simulate Intercept',
  'Layer 7 Proxy', 'Two-Person Quorum', 'Hardware FIDO2',
  'Zero refresh tokens', 'View STS Map', 'View Posture Matrix',
  'GCP Workload Identity', 'alex.mercer', 'Synthetic Principal',
  'v4.18 Engine', 'DENIED & TERMINATED', 'eBPF Syscall Filter',
  'SOC Notification Webhook', 'INTERCEPTED (0.4ms)',
  'Cluster Enforcement Nodes', '18 / 18 ONLINE', 'Average Policy Latency',
  '1.12 ms', 'OPA Compiler Health', 'Rego v0.64', 'OPA Gatekeeper',
  '420 events recorded today', 'All active rules verified',
  'Highest Risk Intercepts', 'Destructive Pattern', 'TTL & Revocation',
  'Device & Posture', 'Quorum & Dual-Control', 'Command Intercepts',
  '4 of 42', 'mTLS Enforced',
  // break-glass (4h) design values, replaced by the live console
  'Shamir', '3-of-5', 'Ernst & Young', 'Signed off by CISO',
  'INC-8812', 'INC-7409', 'INC-6110', '#EPHEM-0x9F3E', '(HSM): LEVEL 4',
  'LEVEL 4 HSM', 'YubiKey 5 FIPS', '42 days ago', 'PD-9921',
  'Global SSO authentication mesh', 'PagerDuty', 'War Room', 'IronMountain',
  'TWOFISH', 'Quorum Custodians', 'HSM Nonce', 'TRNG', 'PCAP',
  'Export Audit Bundle', 'prod-us-east-kms', 'global-root-ca-01',
  '1/3 SHARES', 'Unseal Blocked', 'machine hardware fingerprint',
  'RFC1918', 'SHA-384', 'Okta Outage Drill', '100% Attested',
  'Maria Ramos', 'David K.', 'Emergency Ticket Reference', 'Forensic Rationale',
  'STANDBY STATE', 'ISOLATED ENCLAVE', 'Validate Dispatch Channels',
  'Cryptographic Reconstruction', 'Vault Master Key Split',
  'Last Unseal Event', 'Historical Audit Status', 'Zero-Knowledge Root',
  'Confirm Emergency Break-Glass Unseal', 'Recent Emergency & Drill Log History',
  'Split-K', 'SIMULATION', 'catastrophic',
];

const failures = [];
function check(cond, label, extra) {
  const status = cond ? 'PASS' : 'FAIL';
  console.log(`${status} ${label}${!cond && extra ? ` :: ${extra}` : ''}`);
  if (!cond) failures.push(label);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function sweep(page, mode) {
  const text = await page.evaluate(() => document.body.innerText);
  const hits = FORBIDDEN.filter((f) => text.includes(f));
  check(hits.length === 0, `${mode}: no forbidden strings`, hits.join(' | '));
  return text;
}
const fileUrl = (name) =>
  `file:///${join(REPO, 'frontend', 'screens', name, 'code.html')
    .replace(/\\/g, '/')}`;

const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  for (const name of SCREENS) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1600 } });

    // ---- HTTP mode: real API fills -------------------------------------
    await page.goto(`${BASE}/screens/${name}/code.html`, { waitUntil: 'load' });
    await sleep(1800);
    const httpText = await sweep(page, `${name} http`);
    check(httpText.includes('License server: Healthy'),
      `${name} http: footer filled from /health`);
    check(/Auth: open|auth: open/.test(httpText),
      `${name} http: auth fill = open`);

    // ---- file:// mode: honest static state -----------------------------
    await page.goto(fileUrl(name), { waitUntil: 'load' });
    await sleep(1800);
    const fileText = await sweep(page, `${name} file://`);
    check(!fileText.includes('License server: Healthy'),
      `${name} file://: no live server claim`);
    check(!/Auth: open|auth: open/.test(fileText),
      `${name} file://: no live auth claim`);
    check(/Auth: —|auth: —/.test(fileText),
      `${name} file://: auth dash present`);

    await page.close();
  }
} catch (err) {
  failures.push(`unhandled error: ${err.message}`);
  console.error('ERROR', err);
} finally {
  await browser.close().catch(() => {});
}

console.log('\n---------------------------------------------');
if (failures.length) {
  console.log(`FAILURES (${failures.length}):`);
  for (const f of failures) console.log('  -', f);
  process.exit(1);
} else {
  console.log('ALL CHECKS PASSED');
}
process.exit(0);
