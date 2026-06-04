# Thoth Build Plan

## Purpose

Lay out the first implementation plan for **Thoth**, the analyst-side ingest, triage, and review hub that pairs with **SEKER**.

This plan assumes we keep **SEKER v1 largely as-is for now** and build Thoth around the current bundle contract, tightening that contract only where Thoth ingest requires it.

## Status note

This file remains the roadmap. For the current implemented state, see `docs/thoth-implementation-status.md`.

## Locked requirements

- **Name:** Thoth
- **Collector pairing:** SEKER only in v1
- **Collector platform:** Windows 7 / 10 / 11
- **Windows Server support:** backlog for now
- **Collector mode:** preserve current no-admin baseline, design for later optional elevated mode
- **Elevated backlog priority:** memory capture is a priority for a later SEKER mode
- **Thoth host environment:** macOS first
- **Portability target:** keep the design easy to move to Linux later
- **User model:** single-user, local-only
- **Runtime shape:** CLI ingest/backend plus local web UI for analyst workflow
- **Storage:** SQLite from the start
- **Workflow priority:** triage-first, but allow escalation to deeper review
- **Primary review model:** host-centric
- **Ingest model:** copy-in / staged import, not in-place review from USB
- **Exports:** Markdown and JSON
- **Rules engine:** defer richer rule authoring to v2
- **USB reuse:** eventually support clearing/repreparing SEKER media after ingest

## Key implementation stance

### Do we need SEKER fully provisioned before Thoth?

No.

We need:
- a stable enough sample bundle set
- a stable manifest/hash contract
- a few known artifact shapes to normalize

We do **not** need the collector to be feature-complete before starting Thoth. Thoth can begin now and mature in parallel with selective SEKER contract cleanup.

## v1 outcome

Thoth v1 should let a single analyst on a Mac:

1. import one or more SEKER bundles from USB or a copied folder
2. validate manifests and hashes
3. stage each case into a local workspace
4. store case metadata and review state in SQLite
5. review a host-centric case dashboard in a local web UI
6. inspect core artifact categories and raw files
7. record notes, disposition, and escalation decisions
8. export a concise Markdown or JSON case summary

## Build phases

## Phase 0 — rename + contract lock

Goal: remove naming ambiguity and lock the minimum contract Thoth depends on.

Tasks:
- adopt **Thoth** as the hub name in active planning docs
- keep Thoth doc filenames consistent; old `isis-*` names have been retired
- confirm the minimum required SEKER bundle structure for ingest
- identify any manifest/schema gaps that block ingest confidence

Deliverables:
- this build plan
- updated project docs referencing Thoth
- a short Thoth ingest contract checklist

## Phase 1 — workspace and data model

Goal: stand up the local case workspace and SQLite schema.

Tasks:
- define Thoth workspace layout
- define SQLite schema for:
  - cases
  - case imports
  - integrity results
  - normalized host records
  - findings
  - analyst notes
  - dispositions
  - exports
- define case status values and escalation states

Recommended portable local layout:

```text
thoth/
  bin/
    thoth-ingest
    thoth-review-cli
    thoth-review-api
  lib/
    migrations/
    static/
    templates/
    defaults/
  config/
    thoth.yaml
    suppressions.yaml
    scoring.yaml
  scripts/
    reset-thoth-state.sh
    backup-thoth-data.sh
    doctor-thoth.sh
  logs/
    thoth.log
  data/
    db/
      thoth.sqlite
    imports/
    cases/
      <case-id>/
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

Layout stance:

- keep the install self-contained for portable analyst deployment
- separate immutable app files from mutable case/runtime data
- preserve per-case filesystem legibility even when SQLite is the primary review store

Deliverable:
- initial SQLite schema + workspace bootstrap

## Phase 2 — ingest CLI

Goal: make SEKER bundles operationally importable.

Tasks:
- build CLI command for bundle import
- support source detection from mounted USB path or copied directory
- detect batch and case structure
- copy bundles into Thoth-managed storage
- register cases in SQLite
- support analyst-side case-ID assignment/override during ingest
- capture import logs and error states

Must-have behaviors:
- never trust imported content
- never review directly from USB
- preserve source path/device metadata when available
- allow re-import detection or duplicate warning
- keep analyst-facing case identity separate from low-level collection identity

Deliverable:
- working `thoth ingest <path>` flow

## Phase 3 — integrity validation

Goal: verify what was collected before analysts start interpreting it.

Tasks:
- validate manifest parseability
- validate required files are present
- verify `hashes.sha256`
- record warnings/errors per case
- expose pass/fail/warn summary to CLI and UI

Deliverable:
- machine-readable integrity results stored in SQLite

## Phase 4 — normalization pipeline

Goal: turn the most important SEKER artifacts into stable, queryable records.

First normalized domains:
- host identity
- process inventory
- network connections
- services / scheduled tasks
- persistence entries
- readable log highlights

Tasks:
- write parsers for the current SEKER output set
- preserve source artifact references
- store normalized records in SQLite or structured sidecar files referenced by SQLite
- fail soft on partial/malformed artifacts

Deliverable:
- host-centric normalized case view with partial-data tolerance

## Phase 5 — local web UI

Goal: give the analyst a fast review surface without needing a multi-user system.

Recommended v1 pages:
- Ingest
- Cases
- Case Overview
- Host Overview
- Processes
- Network
- Persistence
- Logs
- Raw Artifacts
- Notes / Disposition
- Reports

UI principles:
- local-only
- dashboard first
- raw evidence always reachable
- integrity status always visible
- low ceremony, high signal

Deliverable:
- local web UI backed by the Thoth CLI/backend and SQLite

## Phase 6 — notes, disposition, and escalation

Goal: make Thoth useful for real analyst decisions.

Tasks:
- support notes per case
- support host-level severity/priority
- support disposition states
- support escalation marker for deeper review
- support next-action text

Suggested disposition states:
- benign / expected
- needs follow-up
- escalate to deeper review
- containment recommended

Deliverable:
- analyst review loop complete end-to-end

## Phase 7 — export

Goal: produce portable case outputs.

Tasks:
- generate Markdown summary
- generate JSON summary
- include integrity status, key findings, notes, and disposition
- preserve evidence references in exports

Deliverable:
- repeatable export flow for case handoff and archival

## Phase 8 — backlog after v1

Not part of the first cut, but intentionally designed for:

- Windows Server SEKER support
- optional elevated SEKER mode
- memory-capture-aware workflows
- richer rules engine / analyst-authored rules
- Linux host deployment for Thoth
- SEKER USB clear/reprepare workflow
- cross-case findings queue and correlation improvements

## Current official backlog

### Locked implementation workflow

#### Tier 1 — analyst workflow blockers

1. case identity flow
2. replace raw-JSON analyst pain
3. artifact/page usability

#### Tier 2 — analyst context and interpretation

4. evidence/source clarity
5. Host Overview enrichment
6. network enrichment

#### Tier 3 — complete review loop

7. notes + disposition
8. report export
9. dashboard improvements
10. suppressions / analyst-tunable rule controls

#### Tier 4 — structural cleanup and scale-up

11. schema tightening
12. cross-case search/correlation
13. platform helpers and VM-friendly enrichment actions

Execution queue for Geo-driven implementation: `docs/thoth-geo-task-queue.md`

### Immediate Thoth priorities

Pre-push / release-gate item:

- package Thoth as a runnable analyst-side executable/portable build before public push; current Thoth workflow still depends on `go run ./cmd/ingest`, `go run ./cmd/review-cli`, and `go run ./cmd/review-api`, while SEKER already has a built Windows executable

1. move analyst-facing case ID creation into Thoth ingest and add a fillable ingest-time case-ID field
2. remove the current editable case-label field from the primary case page once ingest-time Case ID entry exists
3. continue improving findings evidence display beyond the current partial implementation, where PowerShell 4104, scheduled-task, and persistence findings already deep-link to filtered/exact evidence views
4. continue improving normalized artifact-set source clarity beyond the current collected-source links, where bundle-relative paths like `logs/system-events.txt` link to collected-source previews
5. rename or rework normalized artifact-set status labels so ingest/parse success is not misread as analyst judgment
6. keep the Host Identity area, but expand it into a richer Host Overview view and continue replacing raw JSON dumps with analyst-friendly presentation
7. add a Host Overview patch-posture check that estimates distance from current/supported Windows patch level with explicit confidence/limits
8. continue improving log-detail pages beyond the current System Logs landing page, Event ID filtering/display, full-set filtering before pagination, and collection self-noise hints
9. continue artifact-detail record/count polish beyond current true counts and pagination behavior
10. continue network-connections enrichment beyond current protocol/state filters, service labels, public-remote pivot, and PID links
11. add more sortable/filterable network state views so listening, active/established, and closed-style records can be separated quickly
12. add IOC-oriented search/filtering so analysts can search for specific IPs (and later other indicators) quickly across case data
13. continue improving the friendly Persistence page with timestamp/date context where available
14. continue improving the scheduled-tasks view beyond current high-signal fields and parsed date/time sorting for last run, next run, and start time
15. continue improving the process-list view beyond current analyst-friendly labels/search; richer path/PPID context depends on SEKER collection upgrades
1. add case notes + disposition editing in the UI
2. add report export from DB-backed case state
3. improve findings suppressions / analyst-tunable rule controls
4. promote the UI from record dump to a clearer triage dashboard
5. decide where generic normalized tables should become dedicated schemas

### Thoth safety / workflow backlog

- tighten manual source-path entry before any destructive SEKER cleanup/reprep action exists
- keep verifying duplicate-ingest protection under repeated UI and CLI ingest cycles
- add artifact search/filtering
- add a findings queue / stronger home dashboard

### SEKER dependencies that still matter to Thoth

- next SEKER iteration must follow the contamination-aware acquisition order locked in `docs/seker-next-iteration-plan.md`; do not treat the original artifact build priority as runtime command order
- collect readable logs, especially PowerShell Operational, before any PowerShell/WMI/CIM-based collection paths to avoid injecting SEKER-created noise before the log snapshot
- remove the current reused/fallback `case_id` behavior from SEKER manifests so Thoth is not anchored to `CASE-LOCAL-001`-style collector metadata
- file triage collection is still missing but is now deferred to SEKER v2.0; do not include it in the next SEKER collection upgrade pass
- security posture signals are still missing/thin in the baseline collector
- fuller device inventory is still missing/thin in the baseline collector
- boot time / uptime collection is still missing/thin in the baseline collector
- process collection/schema still needs executable path and command-line context where readable
- Wi-Fi context collection is still missing (current SSID/BSSID, adapter state, saved profile metadata where readable)
- Bluetooth context collection is still missing (adapter state, paired devices, recent device indicators where readable)
- some manifest metadata fallback behavior still needs cleanup (`case_id`, username, domain)

### Identity / dedupe stance

- Thoth should own the analyst-facing case ID
- SEKER should keep stable collection identity metadata, not human workflow case numbering
- hostname + collection time is useful collection context and a secondary correlation signal
- stable bundle identity should remain the safer dedupe anchor when available

## Recommended implementation order

1. rename docs and lock contract assumptions
2. define SQLite schema and local workspace
3. build ingest CLI
4. build integrity validation
5. build normalization for core artifacts
6. ship basic local web UI
7. add notes/disposition
8. add Markdown/JSON exports

## Suggested v1 success test

Thoth v1 is good enough when you can:

1. plug in a SEKER USB
2. import a multi-case batch with one command
3. see which cases passed or failed integrity checks
4. open a host-centric case dashboard
5. inspect process/network/persistence/log artifacts
6. record analyst judgment
7. export a Markdown and JSON summary

If it can do that reliably on a Mac without network dependencies, we have a real first release.
