# Incident Response Kit

Two-tier incident response tooling concept to complement the playbooks and TTX work.

## Naming

- **SEKER** = endpoint-side Windows-first collector
- **Thoth** = analyst review / ingest hub

## Goal

Make first-touch triage easy enough for lightly trained staff while preserving enough structure for a stronger central review workflow.

## Proposed shape

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

## High-level folder layout

- `collector/` — endpoint-side USB collector
- `hub/` — analyst review and ingest tooling
- `shared/` — schemas, contracts, bundle formats
- `docs/` — architecture and planning
- `packaging/` — USB and hub packaging/release helpers
- `samples/` — example collector output and test cases
- `releases/` — intentional, checksummed SEKER binaries and validation notes for lab/public preview testing
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

## Next steps

1. define the minimum collector artifact set
2. define the bundle schema
3. support multi-system USB batches cleanly
4. build a single Go collector binary skeleton
5. build the ingest path in the hub
6. add scoring/reporting once the bundle is stable

## Project references

- artifact scope: `docs/v1-artifact-list.md`
- unattended launch notes: `docs/unattended-launch-notes.md`
- Thoth build plan: `docs/thoth-build-plan.md`
- platform feature backlog: `docs/platform-feature-backlog.md`
- Thoth implementation task queue: `docs/thoth-implementation-task-queue.md`
- SEKER operator quick start: `docs/seker-operator-quick-start.md`
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
