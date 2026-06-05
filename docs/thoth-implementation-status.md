# Thoth Implementation Status

## Current state

Thoth is no longer just a concept doc set. It now has a working local foundation for:

- SEKER batch ingest from attached media or batch directories
- copy-in staging into a local Thoth workspace
- manifest/hash integrity registration in SQLite
- first-pass normalization into structured JSON outputs
- loading normalized artifacts into SQLite
- a minimal local web UI for case browsing
- a first findings pass surfaced in the UI

## What works now

### 1. SQLite-backed local workspace

Dedupe support now also has a dedicated bundle-identity store so reusable SEKER media does not have to be wiped immediately to avoid duplicate ingest.

Implemented under `hub/`:

- `hub/go.mod`
- `hub/internal/store/sqlite/`
- embedded schema migrations:
  - `001_init.sql`
  - `002_normalized_artifacts.sql`

Workspace layout in active use:

```text
hub/thoth-data/
  db/thoth.sqlite
  imports/
  cases/<case-uuid>/
    normalized/
    findings/
    notes/
    reports/
```

Target portable install layout (now preferred for packaging/design):

```text
thoth/
  bin/
  lib/
  config/
  scripts/
  logs/
  data/
    db/thoth.sqlite
    imports/
    cases/<case-uuid>/
      source/
      normalized/
      findings/
      notes/
      reports/
      attachments/
    quarantine/
    exports/
    tmp/
```

Important distinction:

- current dev/runtime behavior still centers on `hub/thoth-data/`
- preferred future packaging is a self-contained portable `thoth/` directory with mutable state under `data/`

### 2. Real SEKER ingest

Implemented in:

- `hub/cmd/ingest`
- `hub/internal/ingest/`

Current behavior:

- accepts SEKER USB root, `collections/`, or batch directory input
- detects batch manifests
- stages copied batch content locally
- registers imports and cases in SQLite
- stores host context and integrity summaries
- seeds known bundle identities from already imported case manifests
- skips re-ingest of already known bundles using the stable pair:
  - `batch_id`
  - `bundle_id`

Important note:

- repeated human-facing case IDs like `CASE-LOCAL-001` are **not** used as the dedupe key
- the dedupe key is the bundle manifest identity, which is much safer for reusable media

Validated against the attached SEKER media:

- batch imported: `batch-local-dev-01`
- cases imported: `5`

### 3. Normalization

Implemented in:

- `hub/internal/normalize/`
- triggered via `go run ./cmd/review-cli normalize`

Current normalized outputs:

- host identity
- process list
- network connections
- IP configuration
- route table
- DNS cache
- HKCU Run
- HKCU RunOnce
- startup-folder entries
- scheduled tasks
- application events
- system events
- PowerShell operational events
- Defender operational events

Normalization writes structured JSON files into each case's `normalized/` directory and also loads them into SQLite.

Per-case structure should converge on:

- `source/` — copied source evidence for that case under Thoth control
- `normalized/` — structured artifact transforms
- `findings/` — generated findings artifacts
- `notes/` — analyst notes/disposition material
- `reports/` — rendered outputs
- `attachments/` — optional supporting files or exports tied to the case

### 4. DB-backed normalized artifact store

Implemented with generic tables instead of many premature bespoke schemas:

- `normalized_artifact_sets`
- `normalized_records`

Why this choice:

- gets normalized artifacts into the DB now
- keeps the UI simple to build
- avoids overcommitting to a rigid schema before analyst usage teaches us where to tighten it

### 5. Local review UI

Implemented in:

- `hub/cmd/review-api`

Current behavior:

- local-only HTTP UI on `127.0.0.1:8080`
- home page quick-start link
- home page mounted-source detection for likely SEKER media under `/Volumes`
- home page dropdown selector for detected mounted sources
- home page ingest action that runs ingest + normalize + findings
- case list page
- case detail page
- normalized artifact-set listing per case
- artifact detail pages showing normalized records from SQLite

Current safety note:

- mounted-source auto-detection is safer than a hardcoded path or free-text-only workflow
- manual path entry still exists and should be tightened before destructive media-management actions like SEKER cleanup/reprep are added

### 6. First findings pass

Implemented in:

- `hub/internal/findings/`
- triggered via `go run ./cmd/review-cli findings`

Current rules are intentionally conservative and explainable:

- user-profile HKCU autoruns
- non-default startup-folder items
- scheduled tasks launching from user-profile paths
- PowerShell 4104 script block activity

These findings are written into the existing `findings` table and displayed in the case UI.

### 7. Known-good suppressions + analyst toggle

Implemented in the findings/UI path:

- known-good suppressions are applied to obvious noise like common productivity autoruns and updater tasks
- suppressed findings stay in SQLite; they are not deleted
- case UI defaults to high-signal findings only
- analyst can use the case-page toggle to switch to **Show all** and inspect suppressed items

### 8. Editable case labels + richer headers

Current UI behavior:

- each case has an editable analyst-facing label using the existing `asset_label` field
- label edits persist in SQLite and do not rename raw evidence paths
- case list and case detail headers now surface hostname plus OS version/build information so an analyst gets host context immediately

### 9. Field decision state, analyst notes, and investigation bundle controls

Current UI behavior:

- case list shows a field decision column with disposition, priority, and escalation state
- case detail pages let analysts set disposition, priority, and forensic escalation state
- case detail pages support append-only analyst notes with note type and optional author
- home page can save the current investigation bundle as a tar.gz archive
- analysts can enter a destination directory before saving; the default remains `data/exports`
- home page can clear current imported cases/runtime data after the analyst types `CLEAR`
- clearing the current investigation leaves saved bundles intact

Planned load/restore behavior:

- add **Load Investigation Bundle** for restoring a previously saved `thoth-investigation-*.tar.gz`
- default load mode should replace the active investigation after explicit confirmation
- the UI should tell analysts to save the current investigation first if they need to preserve it
- validate the archive before touching current data; expected shape includes `thoth-data/db/thoth.sqlite` and may include `thoth-data/cases/` and `thoth-data/imports/`
- reject archives with absolute paths, parent-directory traversal, unexpected top-level paths, missing SQLite DB, or symlink/device entries
- restore into a temporary staging directory first, then swap into active `data/` only after validation succeeds
- keep saved bundles/exports intact when replacing the active investigation
- reserve **Merge Into Current Investigation** as a future explicit action, not the default load behavior, because merging requires duplicate case detection and conflict handling for notes, decisions, findings, and imported source paths

## Commands in active use

From `incident-response-kit/hub`:

```bash
go run ./cmd/ingest /Volumes/SEKER
go run ./cmd/review-cli
go run ./cmd/review-cli normalize
go run ./cmd/review-cli findings
go run ./cmd/review-api
```

## What is still rough

- normalized records are in a generic DB store, not a polished analyst schema yet
- findings are useful but noisy and still need suppressions/allowlists for common legit software
- no report export UI yet
- no findings queue/home dashboard yet
- no artifact search/filtering yet
- no multi-user/auth model by design yet
- no Windows Server collector coverage yet
- no elevated SEKER mode yet
- manual path entry is still too permissive for any future destructive media-management flow

## Recent Thoth UI improvements logged

- Host Context has been renamed in visible UI/docs to **Host Overview**; the legacy `/host-context` route remains available for compatibility.
- Host Overview now links to an analyst-friendly Network Configuration page instead of sending analysts directly to raw `network_ipconfig` JSON.
- The main case page links to a **System Logs** landing page rather than listing every log source inline.
- Log pages now run search/level/Event ID filters across the full loaded log record set before pagination and show filtered vs total counts.
- Event IDs are displayed and filterable whenever present.
- Log records near SEKER collection time are shown with visible collection self-noise hints instead of being suppressed.
- The Network view supports remote/public-IP pivots and PID/process links back to the Process page.
- Scheduled-task sorting parses common task time formats for last run, next run, and start time.
- A friendly **Persistence** page now combines HKCU Run, HKCU RunOnce, and Startup Folder records with search/source filters, user-writable-path hints, raw fallback links, and exact record anchors.
- Finding evidence links now point to higher-value destinations for current rule-engine findings: PowerShell 4104 filtered logs, exact scheduled-task anchors, and exact Persistence records.
- The main case page's normalized artifact source column now shows collected bundle-relative source paths such as `logs/system-events.txt` and links to a collected-source preview page at `/cases/{id}/source/{artifact_key}`.

## Immediate next logical steps

1. add a field triage dashboard for multi-system onsite review
2. add Load Investigation Bundle with replace-by-confirmation behavior and archive guardrails
3. add collection completeness / weak-bundle warnings
4. add quick triage export from DB-backed case state
5. add finding suppressions / analyst-tunable rule controls
6. decide where generic normalized tables should become dedicated schemas

## Official backlog detail

### Thoth

#### Pre-push / release-gate items

- package Thoth as a runnable analyst-side executable/portable build before public push; current Thoth workflow still depends on `go run ./cmd/ingest`, `go run ./cmd/review-cli`, and `go run ./cmd/review-api`, while SEKER already has a built Windows executable
- Thoth is not macOS-specific; current web UI/runtime target is macOS or Linux, with Linux VM validation preferred for public preview use
- proposed Thoth 0.1 preview packaging map lives at `packaging/hub/thoth-0.1-preview-build.md`

#### Active next-up

- move analyst-facing case ID creation into Thoth ingest and add a fillable ingest-time case-ID field
- remove the current editable case-label field from the primary case page once ingest-time Case ID entry exists
- add a field triage dashboard for an analyst supervising multiple intern-collected SEKER bundles at a production site; the dashboard should show host identity, collection time, collection completeness, unresolved/severity counts, and top indicators without requiring deep per-host review first
- continue refining host decision status for field outcomes such as monitor, collect more, likely benign, needs follow-up, and forensic escalation; the initial case-list/case-detail UI and persistence are implemented
- flag incomplete or weak collections so analysts know when missing artifacts or normalization failures weaken a field decision
- add Load Investigation Bundle with replace-by-confirmation behavior for previously saved Thoth investigation bundles; defer merge behavior until duplicate/conflict handling is designed
- add quick cross-host pivots for suspicious network traffic, shared remote IPs, persistence entries, scheduled tasks, PowerShell activity, unusual processes, and missing security-control signals
- improve findings evidence display beyond the current partial implementation by storing structured evidence references in dedicated fields instead of encoding refs in evidence text; current rule-engine links already cover PowerShell 4104, scheduled-task anchors, and Persistence anchors
- continue improving normalized artifact-set labeling beyond the current collected-source links, including clearer analyst descriptions and less ambiguous status wording
- rename or rework normalized artifact-set status labels so ingest/parse success is not misread as analyst clearance or benignness
- continue expanding the **Host Overview** page because it now includes identity, network, patch posture placeholders, and other host-level context rather than only identity/context
- keep the Host Identity area, but continue replacing raw JSON dumping with analyst-friendly presentation
- add a Host Overview patch-posture check that estimates how far a Windows host is from current/supported patch level, with explicit confidence and limitations
- continue refining the Host Overview network/ipconfig drilldown, which now has an analyst-friendly network configuration page instead of raw JSON
- add installed-program/software inventory to Host Overview so analysts can quickly compare installed applications against an approved-software baseline or spot unexpected remote-access/admin/security tools
- add USB/removable-device context to Host Overview so analysts can see currently connected USB/removable storage, previously seen USB storage devices, and readable recent USB/device indicators without digging through raw device output
- continue improving log detail presentation beyond the current System Logs landing page, Event ID display/filtering, full-set filtering before pagination, and collection self-noise hints; PowerShell 4104/script-block records should continue improving command/script-block prominence
- continue refining artifact-detail pagination and record messaging; true counts and paging are implemented for raw artifact fallback pages
- continue enriching the network-connections view beyond current protocol/state/search filters, public-remote pivot, common-service labels, and PID links
- continue sortable/filterable network view polish; listening/active grouping, remote-address filtering, external-only pivot, and process links are partially implemented
- add IOC-oriented search/filtering so analysts can search for specific IPs (and later other indicators) quickly across case data
- future upgrade: support searching across multiple devices/endpoints within the same analyst case or incident, so pivots like IPs, process names, users, hashes, and domains can be correlated across hosts; tie this closely to ingest by letting analysts attach an incoming bundle to an existing analyst case/incident via dropdown or create one by manual entry
- continue improving persistence detail pages beyond the current friendly Persistence view, especially timestamp/date context where available
- continue improving the scheduled-tasks view beyond the current high-signal page and date/time sorting for last run, next run, and start time; modified/created timestamps remain pending where source data supports them
- continue improving the process-list view beyond current analyst-friendly labels and case-insensitive partial search; richer command path/PPID depends on SEKER collection upgrades
- continue improving case notes + disposition editing in the UI
- add quick triage export from DB-backed case state, followed by fuller report export
- improve findings suppressions / analyst-tunable rule controls
- promote the UI from record dump to a clearer field triage dashboard
- decide where generic normalized tables should become dedicated schemas

#### Safety / operability

- tighten manual source-path entry before any destructive cleanup/reprep action exists
- keep validating duplicate-ingest prevention across repeated UI and CLI ingest cycles

#### Backlog after that

- artifact search/filtering
- findings queue / stronger home dashboard
- Linux host deployment follow-through
- cross-case correlation improvements

### SEKER items still feeding the backlog

- lock the next SEKER iteration to `docs/seker-next-iteration-plan.md`: minimal preflight, volatile process/network state, contamination-sensitive logs before PowerShell/WMI/CIM, host/session context, execution/persistence inventory, security posture, device/software inventory, then final integrity outputs; file triage is deferred to SEKER v2.0
- immediate sequencing fix: collect readable logs, especially PowerShell Operational, before any PowerShell-based persistence/security/device collectors so SEKER self-noise is visible but not injected before the log slice
- Thoth dependence on SEKER `case_id` has been removed; Thoth assigns analyst-facing Case IDs during ingest and stores SEKER `bundle_id` as Collection ID
- SEKER public CLI no longer exposes `--case-id` or `--dry-run`; dry-run behavior and collector-side fallback `case_id` behavior have been removed
- SEKER keeps/generates `batch_id` for grouping and dedupe; dedupe remains based on `batch_id` + `bundle_id`
- defer file triage collection to SEKER v2.0; next SEKER iteration should focus on host/session enrichment, richer process details, security posture, installed-program inventory, device/removable-media inventory, Wi-Fi/Bluetooth/virtual-adapter context, and metadata cleanup
- add security posture signals, including a quick no-admin Windows Defender and Windows Firewall posture artifact for Host Overview: prefer `Get-MpComputerStatus` fields such as `AMServiceEnabled`, `AntivirusEnabled`, `RealTimeProtectionEnabled`, signature versions/dates, with `WinDefend` service status as fallback/context; collect `netsh advfirewall show allprofiles` for Domain/Private/Public firewall ON/OFF state and default inbound/outbound policy
- add installed-program/software inventory collection using no-admin registry uninstall keys first (`HKLM` 64-bit, `HKLM` WOW6432Node, and `HKCU` uninstall paths); capture display name, publisher, version, install date/source/location, uninstall string when readable, and note limitations for portable apps, Store/UWP apps, and unreliable install dates
- add fuller device inventory collection, including currently connected USB/removable storage and readable USB/PnP device indicators for Host Overview; collect drive letter/mount point, volume label, filesystem, size/free space, bus/interface/removable classification where available, PnP friendly name/device ID/manufacturer/status where readable, and avoid brittle forensic parsing that requires admin or fragile registry assumptions
- implement baseline previous-USB-device collection for Host Overview using readable source-backed evidence first: collect `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `HKLM\SYSTEM\CurrentControlSet\Enum\USB`, `HKLM\SYSTEM\MountedDevices`, and readable USB/storage PnP output; lightly parse device/vendor/product/serial-ish ID, friendly name, source registry path, and mounted volume/drive mapping when available; label confidence as `current`, `previously seen`, or `volume mapping observed`
- defer richer USB timeline reconstruction to a later enrichment pass using `setupapi.dev.log`, device properties, ContainerID/ClassGUID, and user MountPoints2 where readable; do not overclaim first/last-seen timestamps in baseline mode
- collect boot time / uptime where readable in baseline SEKER output
- extend SEKER process collection/schema beyond `tasklist /fo csv /v` to capture executable path, command line, and parent process ID where readable, likely via WMI/CIM (`Win32_Process` / `Get-CimInstance`) with graceful fallback when no-admin permissions limit fields
- add Wi-Fi context collection where readable (current SSID/BSSID, adapter state, saved profile metadata when safely available), then surface it on the Thoth network configuration details page alongside adapter/IP context
- add Bluetooth context collection where readable (adapter state, paired devices, recent device indicators when safely available), then surface it on the Thoth network configuration details page alongside adapter/IP context
- ensure network configuration details clearly identify virtual/container/VM adapters when visible through Windows networking output (for example Hyper-V, WSL, Docker, VMware, VirtualBox, VPN, Npcap/loopback), with review hints so analysts do not confuse virtual/local-only interfaces with primary routed adapters
- continue polishing username/domain presentation where real-world samples expose ambiguity
- later: Windows Server coverage, optional elevated mode, and memory-capture-aware workflows

### Current identity direction

- Thoth should own analyst-facing case IDs
- ingest should allow the analyst to assign or override the case ID during intake
- SEKER collection metadata should not be forced to carry the analyst workflow case ID
- hostname + collection time is useful collection context, but stable bundle identity remains the safer primary dedupe anchor when present
