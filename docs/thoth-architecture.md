# Thoth Architecture

## Summary

**Thoth** is the analyst-side ingest, triage, and review environment for data collected by **SEKER**.

Recommended deployment shape:
- analyst uses a **macOS or Linux laptop**
- Thoth runs primarily inside a **nimble Linux VM** on that laptop
- SEKER bundles are imported into the VM for controlled review

This keeps suspect-host collection and analyst-side interpretation clearly separated.

## Design goals

Thoth should:
- ingest SEKER bundles safely
- validate integrity before review
- normalize raw artifacts into stable reviewable records
- surface high-signal findings quickly
- support analyst notes, disposition, and export
- remain understandable, portable, and field-usable

## Non-goals

Thoth is not, in v1:
- a live-response agent
- a malware detonation environment
- a full forensic lab replacement
- an EDR platform
- a cloud-first SOC backend

## Trust model

### Core assumption
Everything imported from SEKER is **untrusted input**.

### Consequences
- never execute collected binaries or scripts
- do not trust embedded filenames, content, or metadata blindly
- isolate ingest and review from the host OS where practical
- prefer a disposable/snapshot-capable Linux VM for analysis

## Deployment model

### Host layer
The analyst laptop provides:
- operator interface
- transport/storage handling
- optional case coordination tools
- virtualization platform for the Thoth VM

Supported host direction:
- macOS
- Linux

### Thoth VM layer
The Linux VM provides:
- bundle ingest
- integrity validation
- normalization pipeline
- local analyst UI
- case workspace storage
- report export

Preferred VM traits:
- lightweight
- snapshot-friendly
- minimal services
- reproducible build/setup

## Logical components

### 1. Ingest
Responsibilities:
- detect/import SEKER bundle sources
- read batch and case manifests
- verify expected structure
- stage data into an internal case workspace

Inputs:
- removable media
- copied local bundle directories

Outputs:
- registered local case records
- ingest status
- validation results

### 2. Integrity validation
Responsibilities:
- verify manifest parseability
- verify required artifact presence
- verify `hashes.sha256`
- flag malformed, missing, or mismatched artifacts

Outputs:
- integrity summary per case
- error/warning details

### 3. Normalization
Responsibilities:
- parse raw JSON/CSV/TXT artifacts into stable internal records
- preserve source references back to original artifacts
- standardize data for the dashboard and findings engine

Candidate normalized domains:
- host metadata
- processes
- network connections
- persistence entries
- event/log highlights
- security posture signals

### 4. Findings engine
Responsibilities:
- run lightweight rules against normalized data
- generate explainable findings
- attach evidence references

Design preference:
- simple rule-based logic first
- transparent reasons for flags
- no fake precision theater

### 5. Analyst review layer
Responsibilities:
- dashboard summary
- artifact/category drilldown
- notes and disposition
- case status tracking

This is the human decision point.

### 6. Reporting/export
Responsibilities:
- generate concise review summaries
- preserve evidence references
- export analyst notes and disposition

Likely v1 export targets:
- markdown
- JSON summary
- PDF later if needed

## Data flow

1. SEKER writes bundle to response media
2. analyst imports media/bundle into Thoth
3. Thoth validates structure and hashes
4. Thoth stages case into local workspace
5. Thoth normalizes artifacts
6. Thoth runs findings rules
7. analyst reviews dashboard and raw artifacts
8. analyst records disposition and exports summary

## Storage model

Inside the Thoth VM, each case should have:
- imported source reference
- preserved raw bundle copy or staged mirror
- normalized records
- findings data
- analyst notes
- export outputs

Recommended separation:
- `raw/` for imported bundle content
- `normalized/` for parsed records
- `findings/` for rule outputs
- `reports/` for exports
- `notes/` for analyst-authored material

## UI model

Thoth should use a **dashboard-first** review flow.

Core pages:
- Ingest
- Cases list
- Case overview dashboard
- Category drilldowns
- Notes/disposition
- Reports

Reference docs:
- `docs/thoth-ui-page-map.md`
- `docs/thoth-dashboard-notes.md`
- `docs/thoth-analyst-workflow.md`

## Tooling posture

Keep the VM lean.

Good baseline utilities:
- Python
- jq
- ripgrep
- SQLite
- standard hash tools
- local web app/runtime as needed

Deeper forensic tooling should be optional and layered in deliberately.

## Networking posture

Recommended default:
- local-first
- offline-friendly
- no automatic cloud upload during ingest

If enrichment is added later, it should be:
- explicit
- auditable
- easy to disable

## V1 implementation recommendation

For v1, Thoth should prioritize:
1. bundle ingest
2. integrity validation
3. normalized dashboard views
4. analyst notes/disposition
5. report export

That is enough to make SEKER collections operationally useful without overbuilding.
