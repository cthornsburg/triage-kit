# Thoth UI / Page Map

## Goal

Define the first-cut analyst UI for **Thoth** so the product has a concrete shape before implementation.

The UI should support a mobile-response analyst using a Linux VM on a laptop, reviewing bundles collected by **SEKER**.

## Primary navigation

Recommended top-level areas:
1. Home
2. Ingest
3. Cases
4. Case Detail
5. Findings
6. Reports
7. SEKER Media
8. Settings

## 1. Home

Purpose:
- quick entry point for the analyst
- show recent activity and queue state

Key elements:
- recent ingests
- recent cases
- cases needing review
- cases marked escalated
- quick actions:
  - ingest new media
  - open latest case
  - reprepare SEKER USB

## 2. Ingest

Purpose:
- handle intake from SEKER media or copied bundles

Subsections:

### 2.1 Source Selection
- detected removable media
- local folder import
- drag/drop bundle import if UI style supports it

### 2.2 Pre-Ingest Summary
- source device/path
- batch id
- number of cases found
- hostnames found
- collection timestamps
- collector version

### 2.3 Validation Results
- manifest validity
- hash verification status
- missing files
- malformed entries
- warnings/errors from collector

### 2.4 Ingest Action
- import all cases
- import selected cases
- cancel

## 3. Cases

Purpose:
- case list / queue view

Columns or cards should include:
- hostname
- case id
- batch id
- collected time
- status
- warning count
- error count
- disposition
- reviewed/unreviewed state

Filters:
- unreviewed
- escalated
- partial collections
- by hostname
- by batch id
- by date

## 4. Case Detail

Purpose:
- central analyst workspace for a single case

Suggested subpages/tabs:

### 4.1 Overview
Main dashboard page for the case.

Contains:
- case header
- integrity card
- findings summary
- collection coverage
- key highlights
- analyst notes preview

### 4.2 Host Overview
- hostname
- username/domain context
- OS version
- architecture
- timezone
- collected time
- network configuration summary/drilldown
- future installed-program, security posture, USB/removable-device, Wi-Fi/Bluetooth, patch posture, and virtual/device context

### 4.3 Processes
- process list
- flagged processes
- sort/search/filter

### 4.4 Network
- ipconfig summary
- routes
- active connections
- flagged connections

### 4.5 Persistence
- autoruns
- Run / RunOnce entries
- startup folder
- scheduled tasks
- flagged persistence items
- user-writable path hints
- exact finding-to-record anchors where available

### 4.6 Logs
- application events
- system events
- PowerShell operational events
- Defender operational events
- notable entries
- System Logs landing page with per-log review hints
- Event ID display/filtering where present
- visible collection self-noise hints near SEKER collection time

### 4.7 Files / Devices / Security
Reserve area for current or future categories.

### 4.8 Raw Artifacts
- manifest view
- raw text/CSV/JSON artifact browser
- hash/status details
- collected source preview links using bundle-relative source paths such as `logs/system-events.txt`, not only local Thoth storage paths

### 4.9 Notes & Disposition
- analyst notes
- severity/priority
- confidence
- disposition
- next actions

## 5. Findings

Purpose:
- cross-case or per-case flagged-item view

Views:

### 5.1 Findings Queue
- all findings needing analyst review
- grouped by severity or case

### 5.2 Finding Detail
- why it was flagged
- source artifact
- relevant context snippet
- analyst verdict

## 6. Reports

Purpose:
- export and review analyst outputs

Views:

### 6.1 Draft Reports
- generated but not finalized

### 6.2 Export History
- exported summaries
- export timestamps
- target format

Export options for v1:
- markdown
- PDF later if needed
- JSON summary for machine reuse

## 7. SEKER Media

Purpose:
- handle the operational lifecycle of the collector USB after ingest

Views:

### 7.1 Detected Media
- device name
- mount path
- size
- current label
- whether SEKER layout is present

### 7.2 Media Status
- contains unarchived collections?
- safe to reset?
- current collector version on media

### 7.3 Reprepare Action
- wipe/reformat media
- reload current `seker.exe`
- restore instructions/files
- relabel as `SEKER` if desired

Guardrails:
- explicit destructive warning
- device identity shown clearly
- disabled until ingest/validation complete

## 8. Settings

Purpose:
- keep config small and operational

Suggested settings:
- default case workspace location
- hash verification behavior
- artifact normalization toggles
- report export defaults
- SEKER media reload source path
- optional offline/online behavior toggles

## Recommended v1 landing flow

Best default user path:
1. open Thoth
2. go to Ingest
3. review validation results
4. import case(s)
5. land in Case Detail -> Overview
6. drill into flagged categories
7. write notes/disposition
8. export summary
9. optionally reset/reload SEKER media

## UX principles

- dashboard first
- raw artifacts always reachable
- suspicious things surfaced early
- integrity status never hidden
- destructive actions isolated and explicit
- low-friction for the analyst, not cute for its own sake

## Recommendation

If we keep v1 tight, the essential pages are:
- Ingest
- Cases
- Case Detail / Overview
- Notes & Disposition
- SEKER Media

Everything else can stay lean around those core paths.
