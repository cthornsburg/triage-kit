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

### Skip opencode for now
Reason:
- it does not solve the core architecture problem
- it adds another moving part before we have a stable bundle contract
- we can add a preferred coding tool later without changing the product design

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
5. add analyst notes/disposition and exports
6. return later for optional elevated SEKER mode and USB reset/reprepare workflows

## Official backlog snapshot

### Highest-priority next steps

1. move analyst-facing Case ID creation into Thoth ingest and remove dependence on SEKER `case_id` for visible case identity
2. continue replacing raw-JSON-heavy analyst views with analyst-friendly Thoth pages, centered on Host Overview, process list, scheduled tasks, logs, network, persistence, and collected-source fallbacks
3. continue artifact/page usability improvements beyond current true record counts, pagination, sorting/filtering, network-state pivots, and IOC search starting with IPs
4. add Thoth case notes + disposition editing in the UI
5. add Thoth report export from DB-backed case state

### Locked Thoth priority workflow

#### Tier 1 — analyst workflow blockers

1. case identity flow
2. replace raw-JSON analyst pain
3. artifact/page usability
4. Host Overview naming and enrichment

#### Tier 2 — analyst context and interpretation

4. evidence/source clarity
5. Host Overview enrichment
6. network enrichment

#### Tier 3 — complete review loop

7. notes + disposition
8. report export
9. dashboard improvements
10. findings suppressions / analyst-tunable rule controls

#### Tier 4 — structural cleanup and scale-up

11. schema tightening
12. cross-case search/correlation
13. platform helpers and VM-friendly enrichment actions

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
- add report export from DB-backed case state
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
