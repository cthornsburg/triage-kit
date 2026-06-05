# Thoth Quick Start

This is the fast path for an analyst using **Thoth** to ingest and review **SEKER** collections locally.

For the shortest student-facing checklist, start with `docs/thoth-analyst-quick-start.md`. This file keeps a little more implementation context for maintainers and pipeline testing.

## What Thoth does right now

Current working flow:

1. ingest SEKER batch data from a USB or copied folder
2. stage the data locally
3. validate manifests and hashes
4. normalize core artifacts
5. generate first-pass findings
6. review cases in the local web UI

## Before you begin

Target install shape for the portable analyst build:

```text
thoth/
  bin/
  lib/
  config/
  scripts/
  logs/
  data/
```

Within `data/`, Thoth should expect:

```text
data/
  db/thoth.sqlite
  imports/
  cases/
    <case-uuid>/
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

From the workspace root, go to:

```bash
cd incident-response-kit/hub
```

The hub now bootstraps its portable runtime directories automatically on startup, including:

- `data/db`
- `data/imports`
- `data/cases`
- `data/quarantine`
- `data/exports`
- `data/tmp`

Useful helpers:

```bash
./scripts/doctor-thoth.sh
./scripts/reset-thoth-state.sh
./scripts/backup-thoth-data.sh
```

## 1. Ingest the SEKER media

### UI path

Start the UI:

```bash
go run ./cmd/review-api
```

Then open:

```text
http://127.0.0.1:8080
```

From the home page you can now:

- select an auto-detected mounted source from the dropdown, or
- enter a manual source path

Then click:

- **Ingest + normalize + findings**

That runs the current first-pass pipeline from the UI without needing separate CLI commands.

Current safety note:

- the dropdown auto-lists likely SEKER sources under common macOS and Linux mount roots such as `/Volumes`, `/media`, `/run/media`, and `/mnt`
- the manual path field is still more permissive than the future destructive media-action workflow should allow
- before SEKER cleanup/reprep is added, the media-selection flow should be tightened further so internal/system drives cannot be targeted accidentally
- ingest dedupe should now use `batch_id` + `bundle_id`, not repeated human-facing case IDs like `CASE-LOCAL-001`, so reusable SEKER media can stay mounted without automatically creating duplicate cases

### CLI path

If the SEKER USB is mounted at `/Volumes/SEKER` on macOS or `/media/<user>/SEKER-001` on Linux:

```bash
go run ./cmd/ingest /Volumes/SEKER
# or
go run ./cmd/ingest /media/$USER/SEKER-001
```

You can also point Thoth at:

- the SEKER USB root
- a `collections/` directory
- a specific batch directory containing `batch-manifest.json`

## 2. Normalize the imported artifacts

```bash
go run ./cmd/review-cli normalize
```

This writes structured JSON outputs under:

```text
data/cases/<case-uuid>/normalized/
```

and also loads the normalized records into SQLite.

## 3. Generate findings

```bash
go run ./cmd/review-cli findings
```

Current findings focus on:

- user-profile autoruns
- startup-folder items
- user-profile scheduled-task launches
- PowerShell 4104 script block activity

## 4. Start the local review UI

```bash
go run ./cmd/review-api
```

Then open:

```text
http://127.0.0.1:8080
```

## 5. Review a case

In the UI you can:

- open the case list
- see hostname and OS build in the list/header
- edit the analyst-facing case label
- review findings
- toggle between:
  - high-signal findings only
  - all findings, including suppressed known-good noise
- open normalized artifact pages from SQLite-backed data

## One-command working sequence

If you just want the current happy path:

```bash
go run ./cmd/ingest /Volumes/SEKER
# or on Linux
go run ./cmd/ingest /media/$USER/SEKER-001
go run ./cmd/review-cli normalize
go run ./cmd/review-cli findings
go run ./cmd/review-api
```

## Current recommendation

For analysts, prefer the **UI ingestion path** now.

Use the CLI path when:

- debugging ingest behavior
- testing from a terminal
- working on the pipeline itself

## Where Thoth stores data

```text
data/
  db/thoth.sqlite
  imports/
  cases/
  quarantine/
  exports/
  tmp/
```

- `db/thoth.sqlite` = local case database
- `imports/` = staged raw batch content copied from SEKER media
- `cases/<case-uuid>/source/` = copied case source material preserved under Thoth control
- `cases/<case-uuid>/normalized/` = normalized JSON outputs
- `cases/<case-uuid>/findings/` = case-level generated findings artifacts
- `cases/<case-uuid>/notes/` = analyst notes/disposition material
- `cases/<case-uuid>/reports/` = rendered case outputs
- `cases/<case-uuid>/attachments/` = optional supporting files
- `quarantine/` = suspicious or separated material that should not be mixed into normal working sets
- `exports/` = analyst-ready output bundles
- `tmp/` = transient working files

- current dev runs launch from `hub/`, and mutable runtime state is created under `hub/data/`
- this document defines the intended portable install layout for future packaged builds

## Current limitations

This is still an early operator build.

Known limitations:

- findings are intentionally simple and still somewhat noisy
- suppressed findings are based on a first-pass known-good list, not a polished allowlist workflow yet
- notes/disposition editing is not in the UI yet
- report export is not in the UI yet
- dedicated search/filtering is not in the UI yet
- Windows Server support is still backlog on the collector side

## Related docs

- implementation status: `thoth-implementation-status.md`
- build plan / roadmap: `thoth-build-plan.md`
- ingest contract notes: `thoth-ingest-contract-checklist.md`
