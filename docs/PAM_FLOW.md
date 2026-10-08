# VY-PAM — PAM Flow (Application Flow)

**Status:** as-built for Phase 4f (`110909f`)
Maps navigation, user journeys, and state machines across the console.
Screen files live in `frontend/screens/<slug>/code.html`; the canonical
navigation is the 10-item sidebar rendered on every screen.

---

## 1. Screen map & navigation

Sidebar order (slugs = `data-path`, labels = nav text, icons = Material Symbols):

| # | Slug | Label | Icon | Backed by live API |
|---|---|---|---|---|
| 1 | `pam-command-center-threat-dashboard` | Command Center | `grid_view` | ✅ `/overview`, `/events` |
| 2 | `credential-vault-secrets-inventory` | Credential Vault | `vpn_key` | ✅ `/vault/*` |
| 3 | `jit-access-ephemeral-approvals` | JIT Access & Approvals | `hourglass_top` | ✅ `/jit/*` |
| 4 | `live-session-recording-inspection-hub` | Live Session Hub | `terminal` | ✅ `/sessions/*` |
| 5 | `target-infrastructure-connectors` | Target Infrastructure | `dns` | ✅ `/discovery/*` |
| 6 | `policy-zero-trust-rules-engine` | Policy & Zero Trust | `shield_lock` | ✅ `/command-control/*`, `/risk/*` |
| 7 | `compliance-soc-2-audit-center` | Compliance & SOC2 | `policy` | ✅ `/audit/*`, `/events` |
| 8 | `license-entitlement-center` | Licensing & Entitlements | `workspace_premium` | ✅ `/licenses/*` |
| 9 | `break-glass-emergency-protocol` | Emergency Break-Glass | `emergency_home` (rendered in `text-error`) | ⛔ static (`data-kind="static"`) — §17 not built |
| 10 | `platform-settings-center` | Settings | `tune` | ✅ `/settings/*` |

Plus the **launcher** (`frontend/launcher.html`) — a link hub, and the static
spec screens (`enterprise_licensing_…`, `platform_settings_idp_hsm_…`) used as
design references, not navigation.

## 2. Core journeys

### 2.1 License lifecycle (vendor → shipped)

```
VY-Groups (pam_master, :5400)
  keygen (once) → create customer → issue license (RSA-PSS/Ed25519 signed)
  → delivery bundle (.lic + public key + README + SHA256SUMS)
        │  hand-off (out of band)
        ▼
Customer admin (Licensing screen)
  Import (.lic / envelope JSON)
    → verify signature → structure → expiry/quota   [offline, fail-fast order]
    → persist + ledger(source=license)
  → Validate on demand → Usage (real quota counters)
  → Revoke (soft) … Restore   (both audited)
```

Failure paths: bad signature → 400 with stage named; expired → validation
response says so; revoke → subsequent validate reports revoked (and §7/§9
policy can key off entitlement state).

### 2.2 Discovery → onboarding → vault → rotation

```
Discovery & Targets screen
  New scan (≤256 hosts × ≤24 ports, TCP connect, single-flight)
    → running → done/failed
    → assets classified with BASE_RISK, accounts found
  Register / Onboard asset  ──────────────┐
  Ignore asset (keeps record, no manage)  │
                                          ▼
Credential Vault screen                     Target now managed
  New item (type: password/ssh-key/api-token/…)
    → real secret generated (CSPRNG), AES-256-GCM sealed, version 1
  Rotate now (manual) ──┐
  Bulk rotate           │   pipeline: mint → seal → dependents
  Session-end trigger ──┤             → decrypt round-trip → audit
  Scheduler (opt-in) ───┘             (failed → retryable)
  Checkout → use → Revoke checkout / Rotate on return
```

### 2.3 JIT access (request → approval → grant → session → expiry)

```
Requester (JIT screen)
  New request: target + duration + reason + ticket
    → scored (tier, duration, off-hours, repeat, ticket, health)
    → band: low≤25 auto | medium≤50 manager | high≤75 manager+security
            | critical>75 DENY-ONLY (no approval path)
Approvers (same screen, different actor — requester ≠ approver enforced)
  Approve / Deny  → append-only {actor, at, role} snapshots
    → grant (time-boxed, one live session per grant → 409)
      → consume by starting a recorded session (Live Sessions screen)
      → close / expiry → release checkout + rotate credential exactly once
```

### 2.4 Privileged session + command control (the §7/§8/§9 loop)

```
Live Sessions screen → Start session
  ├─ against vault credential   → real checkout
  └─ against active JIT grant   → consume grant
  *** RISK GATE (§7) runs first: evaluation COMMITTED, then:
        critical → 403 details.risk  (refusal stored as SOC evidence)
        high     → allowed only with active JIT grant, else 403
        else     → allowed (RiskEvent row kept either way)
  → session active; events append-only with seq + custody watermark
  → controls enforced live: record/keystroke/clipboard/upload/download/
    screenshot/watermark flags → gated writes keep evidence, never content
Command typed / API evaluate:
  block        → 403 + session ends IF terminate_on_match (cascade:
                 close grant → release checkout → rotate once) → incident inc-<hex>
  approval     → hold → approval row (append-only) → Approve/Deny by other actor
  allow        → passes; default-allow when no rule matches
Operator: pause ▸ lock ▸ resume ▸ terminate/complete
  → cascade + evidence preserved (events kept, metadata stamped)
```

### 2.5 Risk evaluation (console)

```
Policy screen §7 section → Evaluate (advisory)
  inputs: user/asset/device/time/location/context/command/ticket
  → 8-component breakdown (caps 10/15/30/10/5/15/5/10 = 100)
  → band + action (allow/mfa/approval/block)
  → persisted + ledger(source=risk); never blocks anything by itself
```

### 2.6 Compliance & evidence

```
Compliance screen
  Ledger digest (real totals, chain intact/first-break)
  Verify walk (recompute all hashes) → first break index or OK
  Per-source chips (8): license, settings, vault, discovery, jit,
                        session, command, risk  → filter trail
  Export → NDJSON in chain order (SIEM seam)
  Record-inspect modal → one event's full payload
```

### 2.7 Settings change

```
Settings screen → edit group (sso | hsm | zsp | worm)
  → PUT /settings/{group} → per-field diff persisted
  → changelog widget shows actor + before/after (real rows)
```

## 3. Cross-cutting interaction rules

1. **Reveal-on-click only.** Secrets, audit payloads, and other sensitive
   fetches fire **only on explicit click**, and the UI re-masks after 30 s.
2. **Honest fallback.** Opened via `file://` (no backend): controls render
   disabled and every value shows `—`; no fake rows ever appear.
3. **No new IDs in frozen HTML.** Screens may add `data-role` attributes and
   JS-created nodes; structural lookups only — the stitch reference
   (`stitch_pam_suite_dashboard_ui/`) stays byte-frozen.
4. **Every number is live.** If an endpoint errors, the widget shows `—` and
   a truthful error chip — never a cached or sample value.

## 4. State machines

```
VaultItem.status:    available ⇄ checked_out   (rotate/revoke return to available)

JitRequest.status:   pending → approved | denied
                     approved → consumed | expired | closed
                     any → (expired via close job) ; critical never leaves pending→denied path

PrivilegedSession.status:
                     active ⇄ paused ⇄ locked
                     active|paused|locked → terminated | completed
                     (end triggers grant close + checkout release + rotate once)

CommandIncident.status:  open → resolved   (close endpoint, audited)

DiscoveryScan.status: running → completed | failed

Risk band:           low | medium | high | critical   (persisted per evaluation)

Audit chain:         append-only; verify → intact | first_break:<seq>
```

## 5. Roles & separation of duties

| Action | Who (enforced how) |
|---|---|
| Approve JIT | anyone but the requester; security role additionally required on `high` |
| Approve/deny held command | another actor resolves the append-only approval row |
| Reveal secret | authenticated admin; actor recorded; plaintext never logged |
| License import/revoke | authenticated admin; ledger `license` |
| Break-glass emergency access | **not implemented** (§17) — screen static by design |

## 6. Future flows (planned — see `IMPLEMENTATION_PLAN.md`)

Flows below are **not implemented yet**; they show the target journeys the
console will gain, quoted from the architecture doc.

### 6.1 Break-glass emergency (§17 → phase 4h)
```
Break-Glass button / screen → New emergency request (reason + target)
  → emergency authentication → MFA (honest "not configured" until 4i)
  → DUAL APPROVAL (two distinct approvers, append-only snapshots)
  → emergency credential released (real vault checkout)
  → session RECORDED (record forced on) + automatic alert (ledger)
  → close → forced credential rotation + post-incident review note
  → every step auditable under ledger source `break-glass`
```

### 6.2 PAM bypass detection (§10 → phase 4g)
```
Log ingest (auth.log / Windows Event Log export / telemetry)
  → correlate: known principal → managed target with NO active recorded session
  → DIRECT ACCESS DETECTED {user, source, target, protocol, PAM: BYPASSED}
  → Alert SOC · Block source (connector hook or honest "not connected")
  → Create incident · Force credential rotation (real §5 pipeline)
  → evidence preserved in ledger (source `bypass`)
```

### 6.3 Integrations (§20 → phase 4i)
```
Settings → Integrations cards (mfa | itsm | siem | ldap)
  → MFA: TOTP enrol → medium-risk session start requires real code
  → ITSM: ticket key verified against ServiceNow/Jira REST (when configured)
  → SIEM: signed NDJSON batches pushed on ledger append (when configured)
  → unconfigured → chip "not connected" (never simulated)
```

### 6.4 Vendor / third-party access (§13 → phase 5a)
```
Invite vendor → MFA → NDA/Agreement → ticket → approval
  → JIT access (scoped: allowed/denied targets + time window)
  → session recording ENABLED → automatic expiry
  → vendor dashboard shows access ✓ / denied ✗ / validity window / recording
```

### 6.5 DevSecOps & AI-agent access (§15/§16 → phases 5c/5d)
```
Pipeline/Agent → request credential or task access
  → identity verification → risk evaluation → JIT token
  → task-scoped command restrictions (ALLOW restart / DROP → BLOCK)
  → monitored session → token expiry (no static secrets left behind)
```

### 6.6 UEBA anomaly response (§11 → phase 4j)
```
Baseline per actor learned from real history (hours/device/IP/target/command)
  → deviation detected → reasons listed (+unusual time/device/IP/…)
  → BLOCK SESSION → ROTATE CREDENTIAL → SOC ALERT → INCIDENT → EVIDENCE
```
