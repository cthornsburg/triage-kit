# Capstone Project Tracks

These tracks are intended for supervised student collaboration. Each track should be broken into small GitHub issues with clear acceptance criteria.

## Track A - Thoth Analyst Workflow

Best for students interested in UI, analyst experience, and reporting.

Possible deliverables:

- case notes and disposition editing
- Markdown report export
- findings review queue
- dashboard cards for cases needing review
- improved analyst workflow documentation

Starter issues:

- Add a case notes panel to the Thoth case page.
- Add a simple finding disposition selector.
- Export a basic Markdown report for one case.
- Add a dashboard count for unresolved findings.

## Track B - Detection and Findings Quality

Best for students interested in defensive analysis and explainable detections.

Possible deliverables:

- structured evidence references
- better known-good suppressions
- clearer PowerShell 4104 display
- suspicious scheduled-task heuristics
- tests for benign and suspicious examples

Starter issues:

- Add tests for scheduled-task findings.
- Improve PowerShell 4104 event summaries.
- Add a known-good suppression for a documented benign sample.
- Split finding severity from confidence in UI wording.

## Track C - SEKER Collector Validation

Best for students with Windows lab access.

Possible deliverables:

- Windows no-admin validation matrix
- runtime/order validation notes
- artifact size and runtime measurements
- warnings for partial or unavailable artifacts
- synthetic redacted validation bundles

Safety rules:

- Stay inside no-admin baseline collection.
- Do not add file triage to SEKER v1.x.
- Do not collect credentials, browser data, memory, or broad user-file content.

Starter issues:

- Validate SEKER on Windows 10 without admin.
- Validate SEKER on Windows 11 without admin.
- Document behavior when Defender logs are unavailable.
- Document behavior when PowerShell Operational logs are unavailable.

## Track D - Schemas, Samples, and Test Harness

Best for students interested in data modeling and quality gates.

Possible deliverables:

- improved JSON schema validation
- synthetic bundle generator
- malformed bundle tests
- CI workflow
- schema documentation

Starter issues:

- Replace deprecated `jsonschema.RefResolver` usage.
- Add malformed manifest test cases.
- Add a synthetic bundle with missing optional artifacts.
- Add `scripts/check.sh` to CI.

## Track E - Packaging and Operator Experience

Best for students interested in deployment, usability, and field workflows.

Possible deliverables:

- portable Thoth build script
- SEKER USB layout helper
- operator quick-start cards
- doctor/reset/backup polish
- release checklist

Starter issues:

- Add a Thoth portable build script.
- Improve `hub/scripts/doctor-thoth.sh` output.
- Draft a one-page SEKER operator quick start.
- Draft a one-page Thoth analyst quick start.

## Instructor Review Checklist

Before accepting student work, verify:

- `scripts/check.sh` passes.
- The PR is scoped to one issue.
- Any UI change includes screenshots or clear manual test notes.
- Any collector change explains collection/safety impact.
- No real endpoint data or secrets are committed.
- Public docs remain accurate about no-admin and rapid-triage limits.

## Design Review Required

Require maintainer design review before work on:

- elevated collection
- memory capture
- browser artifacts
- credential stores
- broad file enumeration
- real incident data handling
- evidence retention semantics
- destructive media cleanup or reprepare actions
