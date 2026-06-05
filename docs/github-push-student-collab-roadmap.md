# GitHub Push and Student Collaboration Roadmap

Status date: 2026-06-04

## Goal

Prepare the SEKER and Thoth incident response kit project for a public GitHub push and for supervised student collaboration as a capstone project.

The target is not a polished commercial release. The target is a safe, understandable, buildable teaching and prototype repository with clear boundaries, useful first issues, and enough guardrails that students can contribute without accidentally expanding collection risk or publishing sensitive artifacts.

## Current Starting Point

The active prototype workspace is ahead of the current desktop GitHub-ready repository.

Active prototype:

- local working copy used for implementation and planning

GitHub-ready repo:

- clean desktop repository used as the push candidate

Current implementation state:

- SEKER has a working Windows-first Go collector baseline.
- Thoth has working SEKER ingest, SQLite-backed local state, normalization, first-pass findings, and a local review UI.
- Go tests currently pass for both collector and hub.
- Sample manifest validation passes when `jsonschema` is available.
- Documentation is strong internally, but needs consolidation before public contributor and lab use.

## Readiness Definition

The project is ready for a GitHub push when:

- no private/sensitive/local runtime artifacts are committed
- the pushed repo builds from a clean clone
- SEKER and Thoth test commands are documented and passing
- public documentation explains what the tools do and do not do
- contribution guardrails are visible before a student opens code
- issues are scoped for student work and do not require private context
- the active workspace and desktop GitHub repo are reconciled intentionally

The project is ready for student capstone collaboration when:

- students can set up the repo in under an hour
- students can run at least one local sample ingest/review path
- issues are labeled by difficulty, area, and safety risk
- at least one instructor/maintainer review checklist exists
- prohibited work is explicit: credentials, browser history, memory capture, broad file triage, real incident data, and elevated collection paths

## Phase 1 - Repository Reconciliation

Purpose: make one clean source-of-truth repository before polishing.

Tasks:

- Compare the active prototype workspace against the clean GitHub-ready repository.
- Decide whether to promote workspace changes into the desktop GitHub repo or replace the desktop repo with a clean copy of the active workspace.
- Preserve the existing public-facing files from the desktop repo where still valid:
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
- Confirm `.gitignore` excludes:
  - virtual environments
  - local Thoth databases and runtime data
  - generated binaries, except intentional checksummed release artifacts under `releases/`
  - rollback snapshots
  - private notes or memory files
  - real case bundles
- Remove or quarantine repo-internal assistant files that should not ship publicly:
  - `BOOTSTRAP.md`
  - `SOUL.md`
  - `USER.md`
  - `TOOLS.md`
  - local `memory/`
  - `.openclaw/`
- Keep only project-relevant planning docs that help students and maintainers.

Exit criteria:

- one intended push repo is identified
- `git status --short` contains only intended public files
- no local runtime/state files are staged
- sensitive-file scan is clean

Recommended commands:

```bash
git status --short
git diff --stat
find . -name .DS_Store -o -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm'
rg -n "token|secret|password|private key|api key|BEGIN .*PRIVATE|real incident|customer|client" .
```

## Phase 2 - Public Documentation Pass

Purpose: make the repo understandable from a clean GitHub page.

Tasks:

- Rewrite the top-level `README.md` around the public project shape:
  - what SEKER is
  - what Thoth is
  - quick architecture diagram in text
  - who the project is for
  - what is intentionally out of scope
  - current maturity level
- Add or update a short `docs/getting-started.md`:
  - install Go
  - run collector tests
  - run hub tests
  - validate sample manifests
  - run Thoth local UI
- Add or update `docs/student-onboarding.md`:
  - expected skills
  - setup steps
  - recommended first tasks
  - how to ask for review
  - safety boundaries
- Add or update `docs/project-glossary.md`:
  - SEKER
  - Thoth
  - Case ID
  - Collection ID
  - Batch ID
  - bundle
  - artifact
  - finding
  - disposition
- Keep architecture docs, but mark old planning docs clearly as design history if they are not active guidance.

Exit criteria:

- a new student can explain SEKER vs Thoth after reading the README
- setup commands are copy/pasteable
- docs do not imply forensic completeness
- no internal-only workflow assumptions remain in public-facing docs

## Phase 3 - Build and Test Baseline

Purpose: make the project mechanically safe to clone, build, and test.

Tasks:

- Confirm collector tests pass:

```bash
cd collector
go test ./...
```

- Confirm hub tests pass:

```bash
cd hub
go test ./...
```

- Confirm sample manifest validation passes:

```bash
python3 scripts/validate_sample_manifests.py
```

- Add a `Makefile` or `scripts/check.sh` for the common validation path:
  - collector tests
  - hub tests
  - sample schema validation
  - optional build checks
- Add a `requirements-dev.txt` note explaining `jsonschema`.
- Decide whether to keep Python validation or move schema validation into Go later.
- Build local binaries without committing them:

```bash
cd collector
go build -o bin/seker ./cmd/seker
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/seker.exe ./cmd/seker
```

Exit criteria:

- documented validation commands pass from a clean checkout
- no generated binaries are required in the repo
- build outputs are ignored
- students have one obvious "run checks" command

## Phase 4 - SEKER 1.0 Baseline Validation

Purpose: make the collector safe and honest before inviting broad changes.

Tasks:

- Verify the current SEKER version constant and manifest collector version.
- Run a Windows no-admin collection from removable media or a close equivalent.
- Confirm runtime order:
  - volatile state first
  - logs before PowerShell/WMI/CIM-heavy collectors
  - identity and inventory later
  - hashes/manifest last
- Confirm expected artifacts are present:
  - host identity
  - process data
  - network data
  - logs
  - persistence
  - security posture
  - software inventory
  - device/removable-media context
  - hashes
  - errors
  - collector log
- Confirm access-limited conditions are marked partial or warning, not falsely clean.
- Ingest the Windows bundle into Thoth and confirm the review UI renders it.
- Document validation results in `docs/seker-validation-notes.md`.

Exit criteria:

- SEKER can be described as a validated Windows-first baseline collector
- known limitations are documented
- no-admin claim is tested, not assumed
- file triage remains explicitly deferred to SEKER v2.0

## Phase 5 - Thoth Student-Usable Workflow

Purpose: make the hub usable enough for capstone work and demos.

Tasks:

- Confirm Thoth can ingest:
  - synthetic sample bundles
  - current SEKER v1.0 Windows bundle
  - repeated bundle ingest without duplicate case confusion
- Add a short sample workflow:

```bash
cd hub
go run ./cmd/ingest ../samples/collector-output/batch-2026-05-09-01
go run ./cmd/review-cli normalize
go run ./cmd/review-cli findings
go run ./cmd/review-api
```

- Add screenshots or text walkthroughs for:
  - case list
  - Host Overview
  - process page
  - network page
  - logs
  - persistence
  - findings
- Prioritize the next workflow features:
  - case notes and disposition UI
  - report export
  - dashboard polish
  - analyst-tunable suppressions
- Package Thoth as a runnable local build, or clearly label `go run` as the prototype path.

Exit criteria:

- students can run a local Thoth review path without private data
- the UI supports enough review workflow to make capstone contributions meaningful
- missing features are documented as issues, not hidden in chat history

## Phase 6 - Student Contribution Structure

Purpose: turn the project into a good capstone environment.

Tasks:

- Create GitHub labels:
  - `area:seker`
  - `area:thoth`
  - `area:docs`
  - `area:schema`
  - `area:tests`
  - `good first issue`
  - `capstone`
  - `needs design review`
  - `safety-sensitive`
- Create issue templates:
  - bug report
  - feature proposal
  - documentation task
  - student task
  - safety/design review
- Create pull request template requiring:
  - summary
  - validation commands
  - screenshots for UI changes
  - collection/safety impact
  - whether sample data is synthetic
- Create a `docs/capstone-projects.md` menu with task tracks:
  - Thoth UI workflow
  - report generation
  - findings quality
  - schema validation and tests
  - sample data generation
  - packaging
  - documentation
- Seed 10-15 starter issues.

Suggested starter issues:

- Add case notes and disposition editing in Thoth.
- Export a simple Markdown case report from Thoth.
- Add a dashboard card for cases with unresolved findings.
- Add IOC search for IP addresses across a single case.
- Improve PowerShell 4104 rendering in log detail pages.
- Add tests for scheduled-task normalization edge cases.
- Add synthetic sample bundles for missing artifact conditions.
- Add a `scripts/check.sh` validation wrapper.
- Replace deprecated `jsonschema.RefResolver` usage.
- Improve public glossary and README diagrams.

Exit criteria:

- students can pick scoped work without needing private context
- instructors can review work against explicit acceptance criteria
- safety-sensitive changes are visibly gated

## Phase 7 - GitHub Push Checklist

Purpose: make the first public push boring.

Pre-push checks:

```bash
git status --short
git diff --stat
cd collector && go test ./...
cd ../hub && go test ./...
cd ..
python3 scripts/validate_sample_manifests.py
```

Review before staging:

- no `.venv/`
- no `hub/data/`
- no SQLite files
- no ad hoc generated binaries outside documented release artifacts
- no real endpoint bundles
- no local assistant memory or private planning files
- no credentials or secrets
- no private infrastructure references

First push contents should include:

- source code
- schemas
- synthetic samples
- public documentation
- contribution and security policy
- issue and PR templates
- roadmap docs

First push should not include:

- real incident data
- local Thoth databases
- ad hoc generated build outputs
- undocumented binaries
- private notes
- OS metadata
- unpublished classroom roster/context

Exit criteria:

- clean initial commit or small set of intentional commits
- remote GitHub repo visibility is intentionally selected and documented
- README accurately communicates prototype status
- student tasks are available as issues

## Suggested Capstone Tracks

### Track A - Thoth Analyst Workflow

Best for students interested in web UI, incident analysis, and reporting.

Possible deliverables:

- case notes and disposition
- report export
- findings review queue
- dashboard improvements
- screenshots and user guide updates

### Track B - Detection and Findings Quality

Best for students interested in defensive analysis and rule logic.

Possible deliverables:

- improved suppressions
- structured evidence references
- better PowerShell/script-block finding display
- suspicious scheduled-task scoring
- tests for expected and benign cases

### Track C - SEKER Collector Validation

Best for students with Windows lab access.

Possible deliverables:

- Windows no-admin validation matrix
- edge-case collection testing
- artifact runtime and size notes
- improved warnings for partial collection
- synthetic redacted bundle outputs

Safety note:

- This track must stay inside the no-admin baseline unless a maintainer explicitly approves a design review.

### Track D - Schema, Samples, and Test Harness

Best for students who like data modeling and quality gates.

Possible deliverables:

- richer JSON schema validation
- synthetic bundle generator
- malformed bundle tests
- CI workflow
- schema documentation

### Track E - Packaging and Operator Experience

Best for students interested in deployment and usability.

Possible deliverables:

- portable Thoth build script
- SEKER USB layout helper
- doctor/reset/backup polish
- operator quick-start cards
- release checklist

## Recommended Immediate Next Steps

1. Reconcile workspace prototype into the desktop GitHub-ready repo.
2. Remove local/private assistant files from the push candidate.
3. Add public student onboarding docs and issue templates.
4. Add one command for validation, such as `scripts/check.sh`.
5. Run clean build/test/schema checks.
6. Validate SEKER on Windows no-admin media.
7. Seed starter issues for the first capstone sprint.

## Maintainer Rule of Thumb

Accept student contributions that improve clarity, repeatability, validation, review workflow, or synthetic test coverage.

Require design review for anything that expands collection scope, touches credentials, inspects browser data, captures memory, needs elevation, performs broad user-file enumeration, or changes evidence handling semantics.
