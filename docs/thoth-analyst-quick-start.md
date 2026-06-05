# Thoth Analyst Quick Start

This guide is for an analyst or learner using **Thoth** to ingest a SEKER collection, normalize artifacts, generate findings, and review the case locally.

Thoth is a local review hub. It copies SEKER data into its own runtime workspace before review.

## Before You Start

Recommended student setup:

- run Thoth from the packaged preview inside a Linux VM
- follow `docs/thoth-linux-vm-setup.md`

Source-code development setup:

- Git
- Go
- Python 3
- Python package `jsonschema`

From the repo root, run the project check when working from source:

```bash
scripts/check.sh
```

Use synthetic or authorized lab collections only. Do not ingest real endpoint data into a branch intended for public collaboration.

## Start Thoth

### Packaged preview path

From the extracted `thoth-0.1-preview` directory:

```bash
./scripts/doctor-thoth.sh
./scripts/run-thoth.sh
```

### Source development path

From the repo root:

```bash
cd hub
go run ./cmd/review-api
```

Open:

```text
http://127.0.0.1:8080
```

The packaged preview stores runtime data under `data/` inside the extracted package. The source development path stores runtime data under `hub/data/`.

## Ingest A SEKER Collection

In the web UI:

1. Open the ingest view from the home page.
2. Select an auto-detected SEKER source, or enter a manual source path.
3. Optional: enter a human-facing case ID.
4. Click **Ingest + normalize + findings**.

Valid source paths include:

- the SEKER removable-media root
- a copied `collections/` directory
- a specific batch directory containing `batch-manifest.json`

Example manual source path when Thoth was started from the source `hub/` directory:

```text
../samples/collector-output/batch-2026-05-09-01
```

## CLI Fallback

Use the source CLI path when testing pipeline behavior or debugging ingest from a development checkout:

```bash
cd hub
go run ./cmd/ingest ../samples/collector-output/batch-2026-05-09-01
go run ./cmd/review-cli normalize
go run ./cmd/review-cli findings
go run ./cmd/review-api
```

Then open:

```text
http://127.0.0.1:8080
```

## Review Order

Start with:

1. Case list and case header
2. Host overview
3. Findings
4. System logs
5. Process list
6. Network state
7. Persistence artifacts
8. Source artifact preview

Use the findings toggle to switch between high-signal findings and all findings, including suppressed known-good noise.

## Runtime Data

Thoth stores mutable local review data under:

```text
hub/data/
  db/
  imports/
  cases/
  quarantine/
  exports/
  tmp/
```

Helpful maintenance commands from `hub/`:

```bash
./scripts/doctor-thoth.sh
./scripts/backup-thoth-data.sh
./scripts/reset-thoth-state.sh
```

Do not commit `hub/data/`, imported case data, exports, or real endpoint artifacts.

## When Something Looks Wrong

- Run `./scripts/doctor-thoth.sh` from `hub/`.
- Confirm the source path contains `batch-manifest.json` or a `collections/` folder.
- Check whether the SEKER bundle is partial by opening `manifest.json`, `errors.json`, and `collector-log.txt`.
- Use the CLI fallback to separate UI issues from ingest/normalization issues.
- Reset local Thoth state only when you no longer need the current local cases.

For deeper analyst workflow details, see `docs/thoth-user-guide.md` and `docs/thoth-quick-start.md`.
