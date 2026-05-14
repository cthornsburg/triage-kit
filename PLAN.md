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

#### Immediate / near-term

- move analyst-facing case ID creation into Thoth ingest instead of SEKER metadata
- add an ingest-time fillable case-ID field in Thoth so the analyst can assign/override the case identifier during intake
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

#### Immediate / near-term

- remove the current collector-side default/fallback `case_id` requirement from SEKER metadata and manifests
- implement file triage collection
- implement security posture collection/signals, including a quick no-admin Windows Defender and Windows Firewall posture artifact for Host Overview: prefer `Get-MpComputerStatus` fields such as `AMServiceEnabled`, `AntivirusEnabled`, `RealTimeProtectionEnabled`, signature versions/dates, with `WinDefend` service status as fallback/context; collect `netsh advfirewall show allprofiles` for Domain/Private/Public firewall ON/OFF state and default inbound/outbound policy
- implement installed-program/software inventory collection using no-admin registry uninstall keys first (`HKLM` 64-bit, `HKLM` WOW6432Node, and `HKCU` uninstall paths); capture display name, publisher, version, install date/source/location, uninstall string when readable, and note limitations for portable apps, Store/UWP apps, and unreliable install dates
- implement fuller device inventory collection, including currently connected USB/removable storage and readable USB/PnP device indicators for Host Overview; collect drive letter/mount point, volume label, filesystem, size/free space, bus/interface/removable classification where available, PnP friendly name/device ID/manufacturer/status where readable, and avoid brittle forensic parsing that requires admin or fragile registry assumptions
- implement baseline previous-USB-device collection for Host Overview using readable source-backed evidence first: collect `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `HKLM\SYSTEM\CurrentControlSet\Enum\USB`, `HKLM\SYSTEM\MountedDevices`, and readable USB/storage PnP output; lightly parse device/vendor/product/serial-ish ID, friendly name, source registry path, and mounted volume/drive mapping when available; label confidence as `current`, `previously seen`, or `volume mapping observed`
- defer richer USB timeline reconstruction to a later enrichment pass using `setupapi.dev.log`, device properties, ContainerID/ClassGUID, and user MountPoints2 where readable; do not overclaim first/last-seen timestamps in baseline mode
- collect boot time / uptime where readable in baseline SEKER output
- extend process collection/schema to capture executable path and command-line context where readable
- add Wi-Fi context collection where readable (for example current SSID/BSSID, adapter state, and saved profile metadata when safely available), then surface it on the Thoth network configuration details page alongside adapter/IP context
- add Bluetooth context collection where readable (for example adapter state, paired devices, and recent device indicators when safely available), then surface it on the Thoth network configuration details page alongside adapter/IP context
- ensure network configuration details clearly identify virtual/container/VM adapters when visible through Windows networking output (for example Hyper-V, WSL, Docker, VMware, VirtualBox, VPN, Npcap/loopback), with review hints so analysts do not confuse virtual/local-only interfaces with primary routed adapters
- extend SEKER process collection beyond `tasklist /fo csv /v` to capture executable path, command line, and parent process ID where readable, likely via WMI/CIM (`Win32_Process` / `Get-CimInstance`) with graceful fallback when no-admin permissions limit fields
- clean up remaining metadata rough edges around fallback `case_id`, username, and domain fields

### Identity / dedupe decision

- Thoth should own the analyst-facing case ID
- SEKER does not need to be the source of truth for analyst case IDs
- ingest should support a fillable analyst case-ID field at intake time
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
