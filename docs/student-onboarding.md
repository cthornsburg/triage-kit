# Student Onboarding

This project is a supervised capstone-friendly prototype for rapid incident-response triage.

## What You Are Building

The project has two parts:

- **SEKER**: a Windows-first, no-install, no-admin baseline collector that writes a structured triage bundle.
- **Thoth**: a local analyst hub that ingests SEKER bundles, normalizes artifacts, surfaces findings, and supports review workflows.

SEKER is not a full forensic acquisition tool. Thoth is not a cloud SOC platform. Keep changes scoped to rapid triage, repeatable review, and safe teaching workflows.

## Expected Skills

Useful skills include:

- Go basics
- HTML/template/UI basics
- JSON and schemas
- Windows command-line familiarity
- defensive security and incident-response fundamentals
- clear technical writing

You do not need to be an expert in all areas. Pick issues that match your current skill level.

## Setup

Install:

- Git
- Go
- Python 3
- Python package `jsonschema`

Install the Python dependency if needed:

```bash
python3 -m pip install --user jsonschema
```

Clone the repo, then run:

```bash
scripts/check.sh
```

That command runs:

- collector Go tests
- hub Go tests
- sample manifest schema validation

## Run SEKER Locally

For the Windows student/operator workflow, start with:

- `docs/seker-operator-quick-start.md`

Local macOS/Linux SEKER runs are developer harness checks only. They do not validate the Windows collector promise.

```bash
cd collector
go run ./cmd/seker --output-dir ../samples/local-dev-output --hostname WS-LOCAL --operator-id student --media-label USB-LOCAL
```

Do not commit generated `samples/local-dev-output` artifacts unless a maintainer explicitly asks for a synthetic sample update.

## Run Thoth Locally

For the analyst workflow, start with:

- `docs/thoth-analyst-quick-start.md`

Start the local review UI:

```bash
cd hub
go run ./cmd/review-api
```

Open:

```text
http://127.0.0.1:8080
```

Use synthetic sample data only. Do not ingest real endpoint data into a branch intended for public collaboration.

## Contribution Workflow

1. Pick an issue labeled `good first issue`, `capstone`, or your assigned track.
2. Create a branch.
3. Make a small, focused change.
4. Run `scripts/check.sh`.
5. Open a pull request using the template.

Your PR should include:

- what changed
- why it helps
- validation commands run
- screenshots for UI changes
- collection/safety impact

## Safety Boundaries

Do not add or commit:

- real incident data
- credentials, tokens, keys, or secrets
- private IPs or unredacted endpoint artifacts
- browser history collection
- credential-store inspection
- memory capture
- broad user-file triage
- elevated/admin-only collection paths

Anything that expands collection scope needs design review before implementation.

## Good First Areas

- documentation fixes
- synthetic sample improvements
- tests for normalization edge cases
- Thoth UI wording and navigation
- report formatting
- dashboard polish
- validation scripts

## Where To Read Next

- `README.md`
- `PROJECT_MAP.md`
- `CONTRIBUTING.md`
- `docs/capstone-projects.md`
- `docs/github-push-student-collab-roadmap.md`
- `docs/seker-operator-quick-start.md`
- `docs/thoth-analyst-quick-start.md`
- `docs/thoth-quick-start.md`
- `docs/thoth-user-guide.md`
