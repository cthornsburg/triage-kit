# SEKER Geo Task Queue

Implementation queue for Geo-driven SEKER v1.0 work.

Operating mode:
- Chip and Cleo set priority/order.
- Geo implements one contained slice at a time.
- Cleo reviews, verifies, and updates backlog/docs after each slice.
- Keep changes Windows-first, USB-run, no-install, and no-admin for the baseline collector.
- Do not add user-space file triage, targeted file hashing, browser history handling, or broad execution-history parsing in this pass; those are deferred to SEKER v2.0.
- Finished Windows executable version should be **1.0**.

Primary source plan:
- `docs/seker-next-iteration-plan.md`

Current collector entry points:
- `collector/cmd/seker`
- `collector/internal/app`
- `collector/internal/collect`
- current version constant: `collector/internal/app/app.go`

## Locked acquisition order for SEKER v1.0

Geo should preserve this runtime order unless Chip/Cleo explicitly change it:

1. Minimal preflight only
2. Most volatile live state: process and network snapshots
3. Contamination-sensitive logs before PowerShell/WMI/CIM collectors
4. Host identity and user/session context
5. Execution and persistence inventory
6. Security posture
7. Device and installed-program inventory
8. Final integrity outputs

Key contamination rule:
- collect PowerShell Operational logs before any SEKER collector invokes PowerShell, WMI, or CIM.

Hard safety rule:
- never use `Win32_Product`; it can mutate endpoint MSI state.

## Immediate recommended execution order

1. GEO-SEKER-001 — Runtime sequencing correction
2. GEO-SEKER-002 — Collector version 1.0 and metadata cleanup
3. GEO-SEKER-003 — Host/session enrichment
4. GEO-SEKER-004 — Richer process detail with fallback
5. GEO-SEKER-005 — Security posture collection
6. GEO-SEKER-006 — Installed-program inventory
7. GEO-SEKER-007 — Device/removable-media and previous-USB context
8. GEO-SEKER-008 — Wi-Fi/Bluetooth/virtual-adapter context
9. GEO-SEKER-009 — Thoth ingest/normalization/UI follow-through for new artifacts
10. GEO-SEKER-010 — Windows validation and release build

## Task queue

### GEO-SEKER-001 — Runtime sequencing correction

Goal:
- align the current collector runtime order with the locked SEKER v1.0 acquisition order.

Scope:
- update `collector/internal/app/app.go` collector ordering so readable logs run before persistence and before any future PowerShell/WMI/CIM collectors.
- ensure process and network collection run before log collection.
- ensure final metadata, manifest, and hashes still run last.
- make collector stdout / `collector-log.txt` clearly show collection phase order.

Out of scope:
- adding new artifact categories.
- changing Thoth UI.
- adding file triage.

Acceptance checks:
- `PowerShell Operational` log collection happens before the Startup-folder PowerShell command.
- runtime order is visible in code and collector output.
- local dev-harness run still completes.
- existing Thoth normalization still ingests a generated bundle.

### GEO-SEKER-002 — Collector version 1.0 and metadata cleanup

Goal:
- prepare SEKER metadata for the v1.0 finished executable.

Scope:
- set finished collector version to `1.0`.
- remove or neutralize reused/fallback `CASE-LOCAL-001` behavior in production paths.
- preserve stable bundle identity metadata for Thoth dedupe.
- keep hostname + collection time as collection context, not analyst-facing case identity.
- clean up username/domain fallback behavior where currently misleading.
- ensure manifest warnings/errors remain structured and source-specific.

Out of scope:
- changing Thoth analyst-facing case-ID flow.
- broad schema redesign unless a small compatible field addition is required.

Acceptance checks:
- generated manifest reports collector version `1.0` for release builds.
- reusable media does not create ambiguous duplicate analyst case identities.
- Thoth still dedupes by stable bundle identity, not human case ID.
- partial or missing metadata is marked honestly.

### GEO-SEKER-003 — Host/session enrichment

Goal:
- fill Host Overview context without noisy filesystem traversal.

Scope:
- collect boot time / uptime where readable.
- improve current user/profile-path/domain/workgroup fields.
- collect environment/session context where readable and low-risk.
- output either expanded `host/identity.json` or clear separate files such as:
  - `host/uptime.txt`
  - `host/session-context.json`
  - `host/environment.txt`

Out of scope:
- file triage.
- user document enumeration.

Acceptance checks:
- Thoth can display boot time/uptime with source/confidence.
- missing or access-limited fields are marked partial, not silently blank.
- no admin requirement introduced.

### GEO-SEKER-004 — Richer process detail with fallback

Goal:
- improve process pivots beyond `tasklist /fo csv /v`.

Scope:
- collect where readable:
  - PID
  - PPID
  - process name
  - executable path
  - command line
  - owner/user when available
- prefer native Go/Windows API or low-noise collection where practical.
- WMI/CIM is acceptable only after contamination-sensitive logs are collected.
- gracefully fall back to existing `tasklist /fo csv /v` output.

Out of scope:
- process memory inspection.
- elevated-only process introspection.

Acceptance checks:
- restrictive hosts still produce an ingestible process artifact.
- richer fields appear when readable.
- Thoth process page can use PPID/path/command-line fields when present.

### GEO-SEKER-005 — Security posture collection

Goal:
- provide sourced Defender, Firewall, and security-tool posture for Host Overview.

Scope:
- collect Windows Firewall profile posture with `netsh advfirewall show allprofiles`.
- collect Defender posture where readable:
  - `AMServiceEnabled`
  - `AntivirusEnabled`
  - `RealTimeProtectionEnabled`
  - `BehaviorMonitorEnabled`
  - `AntispywareEnabled`
  - `IoavProtectionEnabled`
  - signature versions/dates
  - last quick/full scan fields where readable
- collect `WinDefend` service status as fallback/context.
- collect EDR/security-tool hints from process/service/software names where feasible.

Notes:
- if `Get-MpComputerStatus` is used, it must run after PowerShell Operational logs have already been collected.
- represent third-party AV/EDR and unavailable Defender states with source/confidence, not simplistic pass/fail.

Preferred output:
- `security/firewall-status.txt` or parsed JSON
- `security/defender-status.json`
- `security/security-products.json` or `security/security-tools.txt`

Acceptance checks:
- no admin requirement introduced.
- Defender unavailable/replaced/limited cases degrade cleanly.
- Thoth Host Overview can show Defender and Firewall posture with source/confidence.

### GEO-SEKER-006 — Installed-program inventory

Goal:
- support approved-software comparison and quick spotting of unexpected remote-access/admin/security tools.

Scope:
- collect readable uninstall registry entries from:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- capture fields where present:
  - display name
  - publisher
  - display version
  - install date
  - install location/source
  - uninstall string
  - source hive/path

Hard rule:
- do **not** use `Win32_Product`.

Preferred output:
- `software/installed-programs.json` or `software/installed-programs.csv`

Acceptance checks:
- machine-wide vs per-user entries are distinguishable.
- missing/unreliable install dates are labeled as such.
- Thoth can ingest/display the artifact without raw-registry spelunking.

### GEO-SEKER-007 — Device/removable-media and previous-USB context

Goal:
- give Host Overview a source-backed current and previous USB/removable-device view without claiming full USB forensics.

Scope:
- collect current disk/volume/removable-media state:
  - drive letter/mount point
  - volume label
  - filesystem
  - size/free space
  - removable/bus/interface classification where readable
- collect readable PnP/USB context:
  - friendly name
  - device ID
  - manufacturer
  - class
  - status
  - bus/interface clues
- collect source-backed previous-USB evidence:
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USB`
  - `HKLM\SYSTEM\MountedDevices`
  - readable USB/storage PnP output
- lightly parse obvious vendor/product/serial-ish IDs, friendly names, source registry paths, and mounted volume/drive mappings.

Confidence labels:
- `current`
- `previously seen`
- `volume mapping observed`

Out of scope:
- richer first/last-seen timeline reconstruction.
- fragile `setupapi.dev.log` timeline parsing in baseline v1.0.

Preferred output:
- `devices/volumes.json`
- `devices/pnp-summary.json`
- `devices/usb-current.json`
- `devices/usb-previous.json`

Acceptance checks:
- Thoth clearly separates current vs previously seen vs volume-mapping evidence.
- baseline language does not claim complete USB forensic history.
- output degrades cleanly when keys/devices are missing or unreadable.

### GEO-SEKER-008 — Wi-Fi/Bluetooth/virtual-adapter context

Goal:
- improve network/device interpretation without requiring admin.

Scope:
- collect Wi-Fi context where readable:
  - current SSID/BSSID
  - adapter state
  - saved profile metadata when safely available
- collect Bluetooth context where readable:
  - adapter state
  - paired devices
  - recent device indicators when safely available
- add virtual/container/VM adapter hints from visible network output:
  - Hyper-V
  - WSL
  - Docker
  - VMware
  - VirtualBox
  - VPN
  - Npcap/loopback

Out of scope:
- credential material.
- Wi-Fi keys/passwords.
- deep Bluetooth forensic timeline claims.

Acceptance checks:
- Thoth network details can distinguish likely primary routed adapters from virtual/local-only adapters.
- Wi-Fi/Bluetooth output degrades cleanly when hardware/services are absent.
- no secrets are collected.

### GEO-SEKER-009 — Thoth ingest/normalization/UI follow-through for new artifacts

Goal:
- make new SEKER v1.0 artifacts useful in Thoth, not just present on disk.

Scope:
- update Thoth ingest/normalization for new or expanded artifacts from GEO-SEKER-003 through GEO-SEKER-008.
- surface key fields in Host Overview and relevant detail pages.
- preserve collected-source preview links for raw fallback.
- keep generic normalized tables if that is the smallest safe path; do not force a broad schema redesign unless necessary.

Out of scope:
- report export.
- notes/disposition.
- cross-case correlation.

Acceptance checks:
- imported SEKER v1.0 bundle shows new host/session/security/software/device/network context in Thoth.
- missing artifacts show clear partial/unavailable messaging.
- existing older SEKER bundles still ingest without crashing.

### GEO-SEKER-010 — Windows validation and release build

Goal:
- produce and validate the finished SEKER `1.0` Windows executable.

Scope:
- build canonical Windows binary as `seker.exe`.
- verify manifest collector version is `1.0`.
- run from removable media or equivalent Windows test path.
- confirm output folder shape and artifact names match docs.
- confirm no-admin operation for baseline collectors.
- import resulting bundle into Thoth and run normalization/findings.
- update README/status docs with validation results.

Acceptance checks:
- `seker.exe` runs successfully on Windows without install/admin for baseline scope.
- bundle includes manifest, hashes, collector log, errors/warnings, and expected artifact categories.
- PowerShell Operational log is collected before any SEKER PowerShell collector runs.
- Thoth ingests and displays the new bundle.
- finished exe/version is documented as SEKER `1.0`.

## Handling rules for Geo

- Implement one ticket at a time.
- Keep code/docs changes scoped to the active ticket.
- If a ticket uncovers an architectural blocker, stop and report instead of freelancing a redesign.
- Preserve backward compatibility with older sample bundles when practical.
- Do not add elevated collection or memory capture in SEKER v1.0.
- Do not add file triage in SEKER v1.0.

## Rate-limit-safe execution rules

Use these rules to reduce avoidable model/API pressure while working through the SEKER tickets:

- Prefer **one Geo ticket per run**. Do not ask Geo to implement the whole v1.0 queue in one pass.
- Keep each implementation prompt short and point Geo to this file plus the specific ticket ID instead of pasting large context repeatedly.
- Start with local inspection commands (`grep`, `find`, `go test`, targeted file reads) before asking for broad reasoning over the whole repo.
- Avoid spawning multiple coding agents against the same repo at the same time; serialize SEKER tickets unless Chip/Cleo explicitly split non-overlapping work.
- For large tickets, ask Geo for a short implementation plan first, then approve the smallest coherent slice.
- Prefer deterministic local commands over model calls for verification: `go test`, `go build`, sample collector runs, Thoth ingest/normalize, and targeted diffs.
- Cache decisions in docs after each ticket so the next run can read one source of truth instead of reconstructing context from chat history.
- Keep sample outputs small. Do not generate or ingest many large bundles just to prove a parser path.
- If a provider returns 429/rate-limit errors, stop the current ticket, record the exact blocker, and resume later instead of retrying in a tight loop.
- When using web or external lookups, batch questions and prefer official/local Windows command documentation; do not perform repeated one-off searches for every field.
- Do not run broad formatters or repo-wide rewrites unless the ticket explicitly requires them; they create noisy diffs and larger review burden.
- End each ticket with a compact handoff: changed files, commands run, results, known gaps, and next recommended ticket.
