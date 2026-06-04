# PROJECT_MAP.md

- **Project:** Incident Response Kit
- **Status:** active prototype / student-collaboration preparation
- **Audience:** maintainers, student contributors, instructors, and public-sector security practitioners

## Purpose

Incident Response Kit is a two-tier incident-response toolkit:

1. **SEKER** — a low-touch Windows-first triage collector intended to run from removable media.
2. **Thoth** — an analyst review hub for ingesting SEKER bundles, normalizing artifacts, reviewing findings, and preparing reports.

The project is intended for rapid triage and teaching/research workflows, not full forensic acquisition.

## Start Here

- `README.md` — project overview, naming, scope, and constraints
- `CONTRIBUTING.md` — contribution workflow and safety expectations
- `SECURITY.md` — how to report sensitive data or collection-scope concerns
- `docs/github-push-student-collab-roadmap.md` — roadmap for GitHub readiness and capstone collaboration
- `docs/student-onboarding.md` — setup and contribution guide for students
- `docs/capstone-projects.md` — suggested capstone tracks and starter work
- `collector/README.md` — SEKER collector notes
- `hub/README.md` — Thoth ingest/review notes
- `docs/thoth-quick-start.md` — shortest operator path from SEKER media to Thoth review
- `docs/thoth-user-guide.md` — analyst guide and artifact-review workflow
- `docs/thoth-implementation-status.md` — current implemented state
- `docs/seker-next-iteration-plan.md` — SEKER baseline status and roadmap
- `shared/contracts/bundle-layout.md` — collector-to-hub bundle contract
- `shared/schema/` — schema drafts

## Source of Truth

- architecture decisions: `docs/architecture.md`
- SEKER artifact scope: `docs/v1-artifact-list.md` and `docs/seker-next-iteration-plan.md`
- Thoth implementation status: `docs/thoth-implementation-status.md`
- Thoth build sequence: `docs/thoth-build-plan.md`
- student/public push readiness: `docs/github-push-student-collab-roadmap.md`
- student onboarding and capstone tracks: `docs/student-onboarding.md` and `docs/capstone-projects.md`
- active backlog: `PLAN.md`, `docs/thoth-implementation-status.md`, `docs/thoth-geo-task-queue.md`, and `docs/seker-geo-task-queue.md`
- low-token/small-slice implementation queue: `docs/thoth-low-token-priority.md`
- bundle layout and schemas: `shared/contracts/bundle-layout.md` and `shared/schema/`

## Main Areas

- `collector/` — endpoint-side SEKER collector code
- `hub/` — Thoth ingest, normalization, review API, review CLI, and local UI
- `shared/` — schemas and bundle contracts
- `docs/` — architecture, workflows, roadmaps, and operator guidance
- `packaging/` — packaging/release planning
- `samples/` — synthetic/redacted examples only
- `releases/` — intentional, checksummed release binaries and validation notes for student/lab testing
- `notes/` — non-sensitive backlog notes
- `.github/` — issue and pull request templates

## Common Commands

Collector tests:

```bash
cd collector
go test ./...
```

Hub tests:

```bash
cd hub
go test ./...
```

Sample schema validation:

```bash
python3 scripts/validate_sample_manifests.py
```

Thoth local prototype:

```bash
cd hub
go run ./cmd/review-api
```

## Current Backlog Emphasis

- GitHub readiness: reconcile source, remove unintended generated/runtime artifacts, and tighten public docs.
- Capstone readiness: add student onboarding docs, issue templates, scoped starter issues, and review checklists.
- Thoth next-up: notes/disposition UI, report export, suppressions/rule controls, dashboarding, and portable packaging.
- SEKER next-up: Windows no-admin validation and release documentation for the 1.0 baseline.
- Later: Windows Server coverage, optional elevated collection mode, memory-capture-aware workflows, cross-case search, and richer schema design.

## Safety Rules

- Do not promise forensic-complete collection without elevation.
- Do not collect credentials, browser history, memory, broad user-file content, or elevated-only artifacts without explicit design review.
- Do not commit generated runtime data, real bundles, credentials, private IPs, or unredacted endpoint artifacts.
- Only commit binaries under `releases/` when they are intentional, checksummed, and documented for lab/student use.
- Keep SEKER baseline no-install and no-admin unless a maintainer explicitly approves a separate design path.
- Keep analyst-centric complexity in Thoth; do not leak it into the low-skill collector UX.

## Student Contribution Fit

Good student work:

- tests and validation harnesses
- synthetic sample bundles
- Thoth UI workflow improvements
- report export
- findings quality and explainability
- documentation, onboarding, and diagrams
- packaging scripts and operator checklists

Design-review work:

- expanded collection scope
- elevated collection
- memory capture
- browser data
- credential-related handling
- broad user-file triage
- evidence-handling semantics
