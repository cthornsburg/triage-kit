# Plan

## Goal

Build a two-tier incident response toolkit that lets lightly trained personnel collect a bounded triage package from a suspect endpoint, then move analysis to a separate hub for skilled review.

Current active hub naming: **Thoth**. Legacy `isis-*` filenames have been retired; content and filenames should now read as Thoth.

## Phase 0 — Decision lock

Decide and document:
- supported target OSes for v1
- minimum artifact set for no-admin collection (see `docs/v1-artifact-list.md`)
- case naming convention
- output bundle format
- whether hub starts as CLI-only or CLI + local API

## Phase 1 — Shared contract first

Create in `shared/`:
- manifest schema
- host metadata schema
- artifact inventory schema
- finding schema
- analyst disposition schema

Deliverable:
- one example synthetic bundle in `samples/collector-output/`
- schemas that can represent the V1 artifact set in `docs/v1-artifact-list.md`

## Phase 2 — Collector skeleton

Build in `collector/`:
- Go module
- main `seker` command
- config/profile support
- case folder creation
- manifest writer
- checksum generation
- operator log

Collector design rules:
- no install
- no admin requirement for baseline mode
- quiet and explicit UX
- deterministic output paths

## Phase 3 — Baseline acquisition pack

Implement collectors for:
- host identity
- OS/build info
- process list
- network config
- active connections
- autorun/persistence reachable in user context
- service/task inventory where readable
- user-accessible logs and recent activity
- security tool presence checks

Deliverable:
- first runnable USB triage package

## Phase 4 — Hub ingest

Build in `hub/`:
- bundle validation
- hash verification
- unpack/register case
- normalize raw artifacts into stable records
- simple analyst review CLI

Deliverable:
- import a sample bundle and print a reviewable summary

## Phase 5 — Rules and scoring

Add:
- suspicious process heuristics
- network anomaly heuristics
- persistence heuristics
- missing/disabled security control signals
- simple confidence/severity scoring

Deliverable:
- generated findings list with analyst disposition fields

## Phase 6 — Reporting

Export:
- short executive triage summary
- analyst findings summary
- evidence appendix / artifact map
- next-action recommendations

## Suggested implementation choices

### Use Go for the collector
Reason:
- best match for portable binaries and low dependency pain

### Keep the hub flexible
Start with either:
- Go CLI + local API, or
- Go CLI first, then revisit richer review tooling after schemas settle

### Avoid extra development-tool dependencies for now
Reason:
- it does not solve the core architecture problem
- extra tooling adds another moving part before the bundle contract is stable
- preferred contributor tooling can be documented later without changing the product design

## Risks to manage

- overpromising no-admin coverage
- collecting too much noisy data in v1
- making the operator workflow too clever
- failing to define the bundle schema before coding parsers
- tying the hub too tightly to one environment or external service

## Recommended first coding slice

1. define schemas
2. generate a synthetic sample bundle
3. build `collector/cmd/seker`
4. write manifest + checksums
5. build `hub/cmd/ingest`
6. print a normalized case summary

## Current sequencing note

With the current product decisions, the recommended near-term build sequence is:

1. keep SEKER v1 stable
2. build Thoth ingest + SQLite-backed case model
3. add integrity validation
4. add host-centric review UI
5. add field-triage dashboarding for fast multi-system decision support
6. add analyst notes/disposition and quick triage exports
7. return later for optional elevated SEKER mode and USB reset/reprepare workflows

## Field triage scenario

Primary near-term Thoth planning should account for an analyst taking interns to a production site for suspicious network traffic. Interns may collect multiple endpoints with SEKER while the analyst needs a quick local view to decide whether to keep investigating, mark hosts for additional forensic evaluation, or close out likely-benign systems.

This changes the Thoth emphasis from a single-host review viewer to a field triage command board. The UI still needs deep host drilldowns, but the next workflow layer should help the analyst compare systems quickly, identify incomplete or weak collections, record field decisions, and export a concise triage decision summary.

## Official backlog snapshot

### Highest-priority next steps

1. move analyst-facing Case ID creation into Thoth ingest and remove dependence on SEKER `case_id` for visible case identity
2. add a field triage dashboard for multi-system review with host identity, collection time, collection completeness, severity/unresolved finding counts, and key network/persistence/process/log indicators
3. add host decision status plus case notes/disposition editing in the UI for choices like monitor, collect more, likely benign, needs follow-up, and forensic escalation
4. continue replacing raw-JSON-heavy analyst views with analyst-friendly Thoth pages, centered on Host Overview, process list, scheduled tasks, logs, network, persistence, and collected-source fallbacks
5. add a quick triage export from DB-backed case state that summarizes field decisions, notes, dispositions, and supporting indicators

### Locked Thoth priority workflow

#### Tier 1 — analyst workflow blockers

1. case identity flow
2. field triage dashboard for multi-system decision support
3. collection completeness and weak-bundle warnings
4. host decision status, notes, and disposition capture
5. replace raw-JSON analyst pain

#### Tier 2 — analyst context and interpretation

6. artifact/page usability
7. Host Overview naming and enrichment
8. evidence/source clarity
9. network enrichment

#### Tier 3 — complete review loop

10. quick triage export
11. report export
12. findings suppressions / analyst-tunable rule controls

#### Tier 4 — structural cleanup and scale-up

13. schema tightening
14. cross-case search/correlation
15. platform helpers and VM-friendly enrichment actions

Reference status: `docs/thoth-implementation-status.md`

### Thoth backlog

#### Pre-push / release-gate items

- package Thoth as a runnable analyst-side executable/portable build before public push; current Thoth workflow still depends on `go run ./cmd/ingest`, `go run ./cmd/review-cli`, and `go run ./cmd/review-api`, while SEKER already has a built Windows executable

#### Immediate / near-term

- move analyst-facing Case ID creation fully into Thoth ingest; Thoth should not require SEKER `case_id` in incoming manifests
- add an ingest-time fillable Case ID field in Thoth so the analyst can assign/override the case identifier during intake
- store SEKER `bundle_id` as the collection identity / Collection ID, separate from the analyst-facing Thoth Case ID
- keep duplicate-ingest protection keyed on stable SEKER collection identity, preferably `batch_id` + `bundle_id`, not human case labels
- remove the current editable case-label field from the primary case page once ingest-time Case ID entry exists
- add a field triage dashboard for onsite review across multiple intern-collected systems, with host identity, collection time, collection completeness, unresolved/severity counts, and top indicators visible without opening every host
- add host decision status for field outcomes such as monitor, collect more, likely benign, needs follow-up, and forensic escalation
- flag incomplete or weak collections so field decisions are not made from missing SEKER artifacts or failed normalization
- keep investigation bundle controls analyst-facing: use "Save Bundle As..." for preserving the current cases/notes/decisions/findings/evidence to a selected destination, and "Clear Current Investigation" for resetting the active Thoth workspace while preserving saved bundles
- add "Load Investigation Bundle" for restoring a previously saved Thoth investigation bundle. Default behavior should be replace-by-confirmation, not silent merge: require the analyst to confirm that the current active investigation will be replaced, offer/save-current-first guidance, validate the archive shape before touching current data, then clear active runtime data and restore the bundle. A future "Merge Into Current Investigation" mode can support combining prior work, but it should be a separate explicit action with duplicate/conflict handling rather than the default load behavior.
- for Thoth 0.1 preview testing, do not provide a baseline VM image. Add Linux/macOS build scripts and release docs in this repo first; validate inside a clean Linux VM; use NighHax VM only as optional future guidance/profile after its repo is cleaned up.
- add quick cross-host pivots for suspicious network traffic, shared remote IPs, persistence entries, scheduled tasks, PowerShell activity, unusual processes, and missing security-control signals
- continue improving findings evidence display beyond the current partial implementation, where current rule-engine findings link to PowerShell 4104 filtered logs, exact scheduled-task anchors, and exact Persistence records
- continue improving normalized artifact-set source clarity beyond the current collected-source links, where bundle-relative paths like `logs/system-events.txt` link to a collected-source preview page
- rename or rework normalized artifact-set status labels so ingest/parse success (for example `ok`) is not misread by analysts as investigative clearance or benignness
- visible UI/docs now use **Host Overview**; keep expanding the page because it now includes identity, network, patch posture placeholders, and other host-level context rather than only identity/context
- keep the Host Identity area, but continue expanding it into a more useful Host Overview summary and replacing raw JSON dumping with analyst-friendly presentation
- add a Host Overview patch-posture check that estimates how far a Windows host is from current/supported patch level, with clear confidence/limitations
- continue refining the Host Overview network configuration page/card showing adapters, IPs, gateways, DNS servers, DHCP state, and source/debug detail only behind secondary detail
- add installed-program/software inventory to Host Overview so analysts can quickly compare installed applications against an approved-software baseline or spot unexpected remote-access/admin/security tools
- add USB/removable-device context to Host Overview so analysts can see currently connected USB/removable storage, previously seen USB storage devices, and readable recent USB/device indicators without digging through raw device output
- continue improving log navigation/detail beyond the current System Logs landing page, per-log hints, Event ID display/filtering, full-set filtering before pagination, and visible collection self-noise hints
- continue redesigning log-detail pages with clearer fields, summaries, filtering, and useful event formatting; PowerShell 4104/script-block events should continue improving captured script/command prominence
- continue artifact-detail record/count polish beyond current true counts and pagination behavior
- continue enriching the network-connections view beyond current protocol/state/search filters, service labels, public-remote pivot, and PID links
- continue sortable/filterable network-connection polish so analysts can separate listening, active/established, and closed/time-wait style records quickly
- add IOC-oriented search/filtering so analysts can search case artifacts for specific IPs (and later other indicators) quickly
- future upgrade: support searching across multiple devices/endpoints within the same analyst case or incident, so pivots like IPs, process names, users, hashes, and domains can be correlated across hosts; tie this closely to ingest by letting analysts attach an incoming bundle to an existing analyst case/incident via dropdown or create one by manual entry
- continue improving the friendly Persistence page, especially timestamp/date context where available
- continue improving the scheduled-tasks page beyond current high-signal fields and parsed date/time sorting for last run, next run, and start time; modified/created timestamps remain pending where source data supports them
- continue improving the process-list page beyond current analyst-friendly labels and case-insensitive partial search; richer command/path/PPID context depends on SEKER collection upgrades
- tighten manual path entry before any destructive SEKER cleanup/reprep action exists, so internal/system drives cannot be targeted accidentally
- add case notes + disposition editing in the UI
- add quick triage export from DB-backed case state for onsite decisions, followed by fuller report export
- maintain and expand a Thoth user guide that explains analyst use cases and the "why" behind each artifact area, including Host Overview, collected source previews, process list, scheduled tasks, network state, logs, persistence, findings, and multi-device case review
- improve findings suppressions / analyst-tunable rule controls
- promote the UI from record dump to real triage dashboard
- decide where generic normalized tables should become dedicated schemas
- verify duplicate-ingest prevention stays clean over repeated UI and CLI ingest cycles

#### Later

- artifact search/filtering
- findings queue / home dashboard improvements
- Linux host deployment for Thoth
- cross-case correlation improvements

### SEKER backlog

#### Implemented in current SEKER/Thoth ingest path; keep for regression validation

- public SEKER CLI cleanup: removed `--case-id`, removed `CaseID` config path, removed `--dry-run`, and removed dry-run behavior
- SEKER now generates `batch_id` by default when one is not supplied, while preserving optional operator-supplied batch grouping
- SEKER manifest/batch schemas no longer require collector-side `case_id`; `bundle_id` is the SEKER collection identity
- Thoth ingest no longer requires SEKER `case_id`; it stores SEKER `bundle_id` as Collection ID and keeps duplicate ingest protection on `batch_id` + `bundle_id`
- security posture collection/signals: Windows Firewall via `netsh advfirewall show allprofiles`, Defender posture via `Get-MpComputerStatus`, `WinDefend` fallback, and security-tool hints from process/service names
- installed-program/software inventory from no-admin registry uninstall keys (`HKLM` 64-bit, `HKLM` WOW6432Node, and `HKCU`), including install-date reliability labels and source path metadata
- fuller device/removable-media inventory: volumes, PnP/storage summaries, current USB/removable media, readable bus/interface clues, and confidence labels
- baseline previous-USB-device collection from readable source-backed evidence: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `HKLM\SYSTEM\CurrentControlSet\Enum\USB`, and `HKLM\SYSTEM\MountedDevices`; no complete first/last-seen timeline is claimed
- boot time / uptime and host/session enrichment in `host/identity.json`, with source/confidence and Thoth Host Overview display
- richer process detail after log capture via CIM/WMI-backed `processes/process-details.csv`, including PID, PPID, process name, executable path, command line, and owner where readable, with `tasklist /fo csv /v` fallback
- Wi-Fi context collection via `netsh wlan show interfaces` and profile-name/metadata collection via `netsh wlan show profiles`, without key material
- Bluetooth context collection via readable PnP Bluetooth device/connected-device output; not a forensic pairing timeline
- virtual/container/VM/VPN adapter hints in Thoth network normalization from captured Windows network configuration
- SEKER/Thoth docs and UI labels use: Case ID = Thoth analyst-facing ID, Collection ID = SEKER `bundle_id`, Batch ID = SEKER grouping ID

#### Remaining / deferred

- keep user-space file triage deferred to SEKER v2.0; do not add it to the pre-push baseline
- defer richer USB timeline reconstruction to a later enrichment pass using `setupapi.dev.log`, device properties, ContainerID/ClassGUID, and user MountPoints2 where readable; do not overclaim first/last-seen timestamps in baseline mode

### Identity / dedupe decision

- Thoth should own the analyst-facing Case ID
- SEKER does not expose an operator-facing `--case-id` path in the public baseline collector
- SEKER emits stable collection identity via `bundle_id`; collector-side `case_id` has been removed from the public schema/manifest contract
- SEKER keeps/generates `batch_id` for media/run grouping
- SEKER dry-run/debug collection mode has been removed from the public collector path
- ingest supports a fillable analyst Case ID field at intake time
- dedupe should continue to prefer stable collection/bundle identity rather than a reused human-facing case ID
- hostname + collection time is useful collection context and a secondary correlation signal, but should not replace stable bundle identity where that identity already exists

#### Later

- Windows Server coverage
- optional elevated collector mode
- memory-capture-aware workflow in the elevated path
- SEKER USB clear/reprepare workflow after ingest

### Guardrails / known non-goals for now

- do not promise forensic-complete coverage in the no-admin baseline
- do not add destructive media-management actions until the mounted-source safety model is tighter
- do not add multi-user/auth complexity to Thoth v1 unless the operating model changes
