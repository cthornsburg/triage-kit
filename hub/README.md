# Thoth

Analyst-side ingest and review tooling for SEKER bundles.

## Entrypoints

- `cmd/ingest` — import SEKER USB/batch data into the local Thoth workspace
- `cmd/review-cli` — list cases, run normalization, run findings generation
- `cmd/review-api` — local web UI over the SQLite case store

## Primary job

- validate bundles
- normalize artifacts
- generate explainable findings
- support analyst review and reporting

## Current implementation

- SQLite-backed local case store in `internal/store/sqlite`
- embedded migrations:
  - `migrations/001_init.sql`
  - `migrations/002_normalized_artifacts.sql`
- real SEKER batch ingest in `internal/ingest`
- normalization pipeline in `internal/normalize`
- first findings pass in `internal/findings`
- known-good suppression support with UI toggle for hidden-vs-all findings
- local web UI in `cmd/review-api`
- ingest-time analyst-facing Case ID override in the UI
- hostname + OS build shown in case list/detail headers
- runtime layout detection for dev vs portable installs
- automatic bootstrap of the portable directory tree under `data/`, plus helper scripts for reset/doctor/backup

## Runtime layout

Thoth now targets a portable self-contained runtime shape.

Primary mutable state lives under:

```text
data/
  db/
  imports/
  cases/
  quarantine/
  exports/
  tmp/
```

Per-case layout:

```text
data/cases/<case-uuid>/
  source/
  normalized/
  findings/
  notes/
  reports/
  attachments/
```

Runtime notes:

- current dev runs still launch from `incident-response-kit/hub`
- the hub now defaults to `data/db/thoth.sqlite`
- runtime mode/path detection supports:
  - dev layout (`cmd/`, `internal/` present)
  - portable layout (`bin/`, `lib/`, `config/`, `data/`)
  - explicit `THOTH_ROOT` override

## Quick commands

From `incident-response-kit/hub`:

```bash
go run ./cmd/ingest /Volumes/SEKER
go run ./cmd/review-cli
go run ./cmd/review-cli doctor
go run ./cmd/review-cli normalize
go run ./cmd/review-cli findings
go run ./cmd/review-api
```

Helper scripts:

```bash
./scripts/doctor-thoth.sh
./scripts/reset-thoth-state.sh
./scripts/backup-thoth-data.sh
```

## Reference

- implementation status: `../docs/thoth-implementation-status.md`
