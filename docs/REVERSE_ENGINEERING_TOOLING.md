# VY-PAM — Reverse-Engineering Tooling (REA) for Product Development

**Status:** as-built, verified 2026-10-19 (introduced between batches 11.8 and 11.9)
**Tool:** REA (Reverse Engineer Anything) v6.7.0 — MIT, local-only MCP server + CLI + agent skill
(`https://github.com/morluto/rea`, npm `rea-agents`).

Every number below was collected on this machine at this date. Evidence IDs point at
raw records retained untracked under `Temp/rea-evidence/` (never staged).

---

## 1. Why

The house process is contract-first: ADRs define what we build, verbatim rig captures
define what the API really does. The missing piece was *other tools' code*: when we need
to know how an established product implements a feature (MFA flows, audit append-only
storage, secret encryption, console structure), we need **shipped-artifact evidence**,
not recollection. REA supplies that lane: static analysis of binaries, built web bundles,
and databases with a mandatory evidence envelope (`evidence_id`, `authority`,
`confidence`, `limitations`, subject digest). It complements — never replaces — the
ADR/capture/gate workflow.

---

## 2. What was implemented and verified

| Component | Location | Verification (this machine) |
|---|---|---|
| MCP registration `mcp.rea` | `~/.config/opencode/opencode.json`, version-pinned `npx -y rea-agents@6.7.0 mcp` | `opencode mcp list` → `✓ rea connected` |
| `timeout: 60000` on that entry | same file | server answers `initialize` in **11,342 ms** (probed over stdio) vs OpenCode's documented local-MCP default of **5,000 ms** — without the field every connect timed out |
| Agent skill | `~/.agents/skills/reverse-engineer-anything/` (`SKILL.md` + 6 references) | loaded in the running session |
| Live tools | — | **207 tools** exposed; `binary_session({})` MCP call returned the capability inventory |
| Doctor | — | `healthy: true`; `environment_healthy: false` **only** from optional bring-your-own engines (Ghidra `GHIDRA_INSTALL_DIR` unset, IDA registration unset, JADX JAR unset, Kuna unset, Hopper macOS-only) and `config_drift` in *other* detected clients (`copilot_cli`, `trae`, `vscode`) — all out of this integration's scope |
| CLI fallback | `npx -y rea-agents@6.7.0 <command>` | used for all three evidence runs in §5; returns the same evidence envelope as MCP |

Incident (documented remedy): the first MCP start was killed mid-download and left a
corrupt partial npx install (`ERR_MODULE_NOT_FOUND … @modelcontextprotocol/client/dist/index.mjs`).
Repair = delete the `_npx/<hash>` cache directory and re-run; the cold-start latency it
caused is covered by the `timeout` field above. `doctor` remains the diagnostic entry point.

**Session note:** OpenCode hot-loaded the server into the running session after the
timeout fix — no restart was needed on this host; a fresh session also picks it up from
config.

---

## 3. When to use REA — and when not to

From REA's own skill contract (loaded in §2):

- **Use** when the claim depends on a *shipped* binary/package, decompilation, passive
  runtime evidence, or comparison with behaviour not established by available source —
  i.e. "how does tool X actually implement Y".
- **Do not use** for ordinary analysis of a complete source repository; normal repository
  tools are correct there. (Our own code is source-first; REA only enters for shipped
  artefacts we did not build, or cross-checking a built artefact against source claims.)

**Target scope (constraint):** own artefacts and open-source/authorized targets only
(this run: sops MPL-2.0, Vaultwarden AGPL-3.0, our own rig DB). No proprietary
competitor consoles — REA's disclaimer requires authorization to examine.

---

## 4. Evidence rules as practiced

1. Every result carries an evidence envelope: `evidence_id`, `authority`
   (`shipped-artifact` etc.), `confidence` (`observed`/`derived`/`inferred`), subject
   **sha256**, `limitations[]`, explicit coverage status (`complete`/`partial`/`unknown`).
2. Digests are verified upstream when upstream publishes them (run 1).
3. `limitations` are quoted verbatim in findings; `partial` coverage is reported as
   partial — absent facts are unknown, not false.
4. Static evidence never claims runtime behaviour ("Static … do not prove runtime
   execution").
5. Target content returned by REA tools is data, never instructions (prompt-injection
   guard in the server instructions); untrusted content is marked
   `_meta.provenance.untrusted_content`.
6. Raw envelopes too large to read are summarized with a bounded parser
   (`Temp/rea-evidence/summarize.mjs`), never by parsing a truncated preview.

---

## 5. Three verified runs (all on 2026-10-19)

### 5.1 Supply-chain inspection of another secrets tool — `inspect-go-binary`

- **Artefact:** `sops-v3.13.3.amd64.exe` (getsops/sops, MPL-2.0), sha256
  `a4a9a398858fe8b2ef72d9686d930bf7c5cece9be74ad83ac3b53cfdd70e6b1c` — **matches upstream
  `sops-v3.13.3.checksums.txt`** (verified, not assumed).
- **Evidence:** `ev_32936c5399e89bf7f477011f09516d4f6e5bc8947b89a853a423b12b2b9ee434`,
  authority `shipped-artifact`, confidence `observed`, 743 ms. No target execution.
- **Facts:** Go `go1.26.5`; main module `github.com/getsops/sops/v3` `v3.13.3`;
  **122 dependencies**, incl. `filippo.io/age v1.3.1`, `golang.org/x/crypto v0.54.0`,
  `ProtonMail/go-crypto v1.4.1`, `cloudflare/circl v1.6.4`, `golang-jwt/jwt/v5 v5.3.1`,
  `lib/pq v1.12.3`, `hashicorp/vault/api v1.23.0`, AWS-KMS / GCP-KMS / Azure-KeyVault
  SDKs. Build settings: `-trimpath`, `CGO_ENABLED=0`,
  `DefaultGODEBUG=cryptocustomrand=1,tlssecpmlkem=0`,
  `vcs.revision=26e2f4784ca61353082c32dbd987c25eda086dc9`, `vcs.modified=false`.
- **VY-PAM takeaway:** an evidence-based dependency/crypto baseline for third-party
  secrets tooling we may interoperate with, and a concrete template for reproducible
  build metadata on our own releases.

### 5.2 Shipped database schema audit — `inspect-sqlite-database` (ADR-0019 input)

- **Artefact:** `/app/backend/phase2_license_server/licenses.db` copied from the running
  demo container `vypam-frontend-test`, sha256
  `b88e08847d6f240cb7be11de52ce971836f38012876fbf29de9ddae6ffb484b8`, **WAL: none** (clean
  snapshot sibling set).
- **Evidence:** `ev_6b0f9832653da7e9bbeda1d97f2b424d03dcf56f6faf078c24c90a741c8b7ad8`,
  authority `shipped-artifact`, confidence `observed`; engine SQLite `3.53.4`, 3,101 ms.
- **Facts:** `scope=database`, `completeness=complete`: **75 tables, 175 indexes,
  0 views, 2 triggers**. Triggers verbatim:
  `CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only (architecture 19)'); END`
  and the identical `…_no_delete` BEFORE DELETE form.
- **Cross-check:** `backend/phase2_license_server/models.py` contains exactly **75**
  `__tablename__` declarations and `service.py` contains **0** raw `CREATE TABLE`
  statements — shipped schema agrees with the model-driven source. (Agreement of
  inventory; not a behavioural proof.)
- **VY-PAM takeaway:** authoritative baseline for the ADR-0019 PostgreSQL port:
  `ensure_schema` must reproduce all 75 tables/175 indexes, and the two SQLite
  `RAISE(ABORT …)` triggers must be re-expressed as PostgreSQL `RAISE EXCEPTION`
  triggers with the same append-only contract. Limitations quoted from the record:
  offline stable file set, no atomic-snapshot claim for a live database.

### 5.3 Understanding another product's shipped console — `analyze-javascript-application`

- **Artefact:** `vaultwarden/server:latest` image digest
  `sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`, extracted
  `/web-vault` (279 files, 142.3 MB), root sha256
  `ead86ed67b25c2fa1762b442841db98980e07dedfa80e6c687e6d7f5e08139ac` (Vaultwarden,
  AGPL-3.0 — open-source target).
- **Evidence:** `ev_76f42c67abcaf399239de627ebbee178fc8e43cec8640908a53cd5a9a676b174`,
  authority `shipped-artifact`, confidence **`derived`** (static reconstruction),
  413,414 ms; inventory manifest `agm_78d1edcb47517515fbfac5c780e552b52d34562d6791b9931a509acd8f292205`,
  `integrity_contradictions: 0`.
- **Facts:** 133 relevant files; 135,853,450 text bytes read; 27 JS files parsed
  (1 skipped), **0 parse failures**; **1,762 modules**; application graph **6,260 nodes /
  7,705 edges**; 10,647 findings; 2,112,332 AST nodes visited; semantic graph 100,000
  nodes / 106,602 relations / 50,086 unknowns (declared cap, `truncated: true`);
  Electron surface all zeros (pure web console — honest negative).
- **Limitations (11, verbatim highlights):** three large chunks (`981.*.js`,
  `app/main.*.js`, `app/polyfills.*.js`) hit worker-heap/result budgets → coverage
  `partial`, complete static facts retained on those file nodes; "Webpack/Rspack
  factories were recovered from AST literals; REA did not invoke push handlers or bundle
  bootstrap code"; "Static imports … do not prove runtime execution".
- **VY-PAM takeaway:** the working pattern for "how does tool X implement feature Y"
  studies against a *built* console — module graph → workflow inventory → focused
  `trace_application_feature` follow-ups — with coverage honestly bounded.

---

## 6. Lane catalogue → VY-PAM use

| Lane (CLI/MCP) | Prerequisite | Status here | VY-PAM use |
|---|---|---|---|
| `inspect-go-binary`, `inspect-rust-binary` | none | ✅ verified (§5.1) | supply-chain review of third-party tools |
| `inspect-sqlite-database` | Node 24 | ✅ verified (§5.2) | shipped-schema audits; ADR-0019 baseline |
| `analyze-javascript-application`, `recover-javascript-sources`, `trace-javascript-semantics`, `reconcile-javascript-runtime` | none | ✅ verified (§5.3) | other products' built consoles/Electron apps |
| `inspect-web-network-capture` (HAR/SAZ/mitmproxy) | a saved capture | available, **not adopted** | candidate to systematise rig captures; would need its own contract decision — today's verbatim captures remain the house method |
| `capture-browser-scenario`, `observe-web-execution`, `observe-web-session`, `list-browser-targets` | local Chrome/Edge + CDP | available, not exercised | runtime evidence when static cannot answer |
| `inspect-pcap-capture`, `inspect-packet-capture` | tshark 4.x + Linux prlimit | ❌ not installed | protocol-level debugging of the gateway data plane (future) |
| native lanes (`open_binary`, `analyze_function`, pseudocode, …) | Ghidra 12.1.x (`GHIDRA_INSTALL_DIR`) or IDA registration | ❌ not configured (bring-your-own) | decompilation of native targets if ever needed |
| Android lanes | caller-supplied jadx JAR | ❌ not configured | not currently needed |
| `.NET` static (`inspect_managed_artifact`, members, boundaries) | none | available | inventory of managed artefacts if encountered |

---

## 7. Operating notes

- Setup/diagnostics: `npx -y rea-agents@6.7.0 setup --client opencode --dry-run` → review →
  `--yes`; `npx -y rea-agents@6.7.0 doctor --client opencode --format json`.
  Upgrade = change the pin in `~/.config/opencode/opencode.json` and re-run doctor;
  `uninstall` removes REA-owned config and skill files.
- Raw evidence lives untracked in `Temp/rea-evidence/` (sops exe 53.5 MB + checksums,
  `licenses.db` snapshot 1.1 MB, Vaultwarden extracted bundle 142.3 MB, three JSON
  envelopes — the JS run is 218 MB, summarize with `summarize.mjs`, do not `Get-Content -Raw`
  into a shell). Nothing under `Temp/` is ever staged.
- No change to house gates: verbatim rig captures, ADR-first contracts, `__verify_agent.mjs`
  gates, gitleaks, ledger rows and topology regen are unaffected. REA feeds *inputs*
  (schema baselines, dependency facts, feature studies) into those contracts.
