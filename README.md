# Incident Response Kit

Two-tier incident response tooling concept to complement the playbooks and TTX work.

## Naming

- **SEKER** = endpoint-side Windows-first collector
- **Thoth** = analyst review / ingest hub

## Goal

Make first-touch triage easy enough for lightly trained staff while preserving enough structure for a stronger central review workflow.

### Disclaimer

SEKER and Thoth are educational and research projects developed for instructional use, laboratory exercises, and rapid incident-triage workflows. These tools are intended to assist with preliminary system assessment and are not designed to replace professional incident response, digital forensics, or comprehensive evidence acquisition procedures.

Use these tools only on systems that you own, administer, or are explicitly authorized to assess. Users are responsible for ensuring compliance with applicable laws, organizational policies, and ethical standards.

Because SEKER emphasizes lightweight, no-install collection and operation without administrative privileges, some artifacts may be incomplete, unavailable, or unsuitable for evidentiary purposes. Data collected by SEKER should not be considered a complete forensic record.

For instructional activities, use synthetic, anonymized, or otherwise approved datasets whenever possible. Do not collect, share, store, or publish credentials, personal information, proprietary data, or other sensitive artifacts without proper authorization.

SEKER output should be treated as untrusted input. Thoth and any associated analysis components should be operated in a controlled environment, such as an isolated workstation or virtual machine, particularly when used for testing, research, or classroom activities.

The authors and sponsoring institution provide these tools "as is" without warranty and assume no responsibility for misuse, data loss, operational disruption, or legal consequences arising from their use.

## Current Shape

### Tier 1 — USB Collector
Portable, low-touch collector that runs from removable media on a suspect endpoint.

Design targets:
- no install
- no admin required for baseline triage
- minimal prompts
- clear operator instructions
- writes results back to the USB in a predictable case bundle
- works even when the operator is not deeply technical

Best fit:
- **Go** for the collector/orchestrator
- static binaries per platform
- optional platform-specific helpers only when truly needed

### Tier 2 — Analysis Hub
A separate review environment where experienced analysts ingest collected bundles, normalize findings, triage alerts, and produce reports.

Design targets:
- never depend on the suspect host
- central scoring and review
- repeatable ingest pipeline
- case-by-case analyst notes and disposition

Preferred install shape:

- self-contained portable Thoth directory
- separate app/runtime/config/data areas inside that portable folder
- per-case folders that remain filesystem-legible even when SQLite is the main review surface

The current Thoth 0.1 preview package is published as a GitHub prerelease for supervised student and contributor testing:

- `docs/thoth-linux-vm-setup.md` — run the preview package inside a normal Linux VM
- `docs/thoth-analyst-quick-start.md` — ingest and review a SEKER bundle

## High-level folder layout

- `collector/` — endpoint-side USB collector
- `hub/` — analyst review and ingest tooling
- `shared/` — schemas, contracts, bundle formats
- `docs/` — architecture and planning
- `packaging/` — USB and hub packaging/release helpers
- `samples/` — example collector output and test cases
- `releases/` — intentional, checksummed SEKER binaries, Thoth preview archives, and validation notes for lab/public preview testing
- `notes/` — working notes and decision log

## Important constraint

"No install and no permissions" is realistic for **baseline triage**, not for every forensic need.

Without elevation, expect good access to:
- hostname / user / time / OS details
- running processes
- network config and connections
- autoruns accessible to the current user
- basic logs and recent activity that user context can read
- file-system triage in accessible locations

Without elevation, expect limited or no access to:
- memory capture
- protected event logs
- kernel artifacts
- many security product stores
- protected registry hives / system databases
- some browser and credential stores

That means the first release should be honest: **rapid triage collector**, not full forensic acquisition.

## Current Preview Path

For student testing:

1. Use `docs/seker-operator-quick-start.md` to collect synthetic or approved Windows lab data with SEKER.
2. Use `docs/thoth-linux-vm-setup.md` to run Thoth inside a Linux VM.
3. Use `docs/thoth-analyst-quick-start.md` to ingest and review the bundle.

Do not use real endpoint data for public coursework or public repository examples.

## Project references

- artifact scope: `docs/v1-artifact-list.md`
- unattended launch notes: `docs/unattended-launch-notes.md`
- Thoth build plan: `docs/thoth-build-plan.md`
- platform feature backlog: `docs/platform-feature-backlog.md`
- Thoth implementation task queue: `docs/thoth-implementation-task-queue.md`
- SEKER operator quick start: `docs/seker-operator-quick-start.md`
- Thoth Linux VM setup: `docs/thoth-linux-vm-setup.md`
- Thoth analyst quick start: `docs/thoth-analyst-quick-start.md`
- Thoth quick start: `docs/thoth-quick-start.md`
- Thoth user guide: `docs/thoth-user-guide.md`
- Thoth ingest contract checklist: `docs/thoth-ingest-contract-checklist.md`
- Thoth platform notes: `docs/thoth-platform-notes.md`
- mobile response workflow: `docs/mobile-response-workflow.md`
- Thoth v1 features: `docs/thoth-v1-features.md`
- Thoth architecture: `docs/thoth-architecture.md`
- analyst workflow: `docs/thoth-analyst-workflow.md`
- dashboard notes: `docs/thoth-dashboard-notes.md`
- UI / page map: `docs/thoth-ui-page-map.md`
- bundle layout: `shared/contracts/bundle-layout.md`
- schema drafts: `shared/schema/`
- sample manifest validator: `scripts/validate_sample_manifests.py`
- dev deps: `requirements-dev.txt`
- student onboarding: `docs/student-onboarding.md`
- capstone project tracks: `docs/capstone-projects.md`
