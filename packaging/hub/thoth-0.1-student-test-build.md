# Thoth 0.1 Student Test Build Plan

## Purpose

Create a student-testable Thoth build without calling it a finished release.

Thoth 0.1 should let a student analyst run the local review UI, ingest synthetic or lab SEKER bundles, record field decisions/notes, save or clear an investigation bundle, and exercise the current workflow without needing Go installed.

## Platform Target

Thoth is not macOS-specific. The web UI is a local Go HTTP server backed by SQLite and filesystem storage.

Supported test targets for 0.1:
- macOS arm64
- macOS amd64 if needed
- Linux amd64

Preferred analyst environment remains a lightweight Linux VM on a response laptop. The macOS build is useful for development and instructor demos; Linux should be validated before calling the package student-ready.

Do not target Windows for Thoth 0.1 unless a maintainer explicitly approves that scope. SEKER is Windows-first; Thoth is analyst-side review tooling.

## VM Scope Decision

Do not provide or maintain a baseline VM image for Thoth 0.1.

For the student test build, package Thoth from this repository first:
- build Linux and macOS binaries
- include release docs and checksums
- validate the Linux build inside a clean VM
- document how students can run Thoth inside a Linux VM

NighHax VM is a suitable optional Linux VM base, but it should not become a dependency of Thoth 0.1. Treat NighHax integration as later guidance or a future profile after the existing NighHax repo is cleaned up. This keeps the initial Thoth release focused and avoids maintaining a VM image, credentials, snapshots, guest additions, hypervisor quirks, and update drift before the app package itself is stable.

## Release Directory Shape

Proposed committed release path:

```text
releases/thoth/0.1/
  bin/
    thoth-review-api-<os>-<arch>
    thoth-ingest-<os>-<arch>
    thoth-review-cli-<os>-<arch>
  lib/
    docs/
      thoth-quick-start.md
      thoth-user-guide.md
      thoth-analyst-quick-start.md
  BUILD_NOTES.md
  VALIDATION.md
  SHA256SUMS.txt
```

Runtime-created mutable folders should not be committed:

```text
data/
logs/
tmp/
```

## Build Commands

From `hub/`:

```bash
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../releases/thoth/0.1/bin/thoth-review-api-darwin-arm64 ./cmd/review-api
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../releases/thoth/0.1/bin/thoth-ingest-darwin-arm64 ./cmd/ingest
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../releases/thoth/0.1/bin/thoth-review-cli-darwin-arm64 ./cmd/review-cli

GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ../releases/thoth/0.1/bin/thoth-review-api-linux-amd64 ./cmd/review-api
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ../releases/thoth/0.1/bin/thoth-ingest-linux-amd64 ./cmd/ingest
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ../releases/thoth/0.1/bin/thoth-review-cli-linux-amd64 ./cmd/review-cli
```

## Student Run Path

From the extracted Thoth release root:

```bash
export THOTH_ROOT="$PWD"
./bin/thoth-review-api-linux-amd64
```

Then open:

```text
http://127.0.0.1:8080
```

Students should test with synthetic or instructor-provided lab bundles only. Do not use real endpoint data for public/classroom validation.

## 0.1 Validation Checklist

Before committing binaries:

- `scripts/check.sh` passes from repo root.
- Clean-clone build script produces binaries into `releases/thoth/0.1/bin/`.
- `SHA256SUMS.txt` contains all committed binaries and release docs.
- `BUILD_NOTES.md` records source commit, build host, Go version, commands, and date.
- `VALIDATION.md` records tested OS/architecture and exact validation steps.
- macOS build starts the local UI and shows the home page.
- Linux amd64 build starts the local UI inside a Linux VM and shows the home page.
- Synthetic sample SEKER bundle ingests through the UI.
- Case page renders Host Overview, findings, field decision, and notes.
- Save Bundle As... writes a `thoth-investigation-*.tar.gz`.
- Clear Current Investigation resets active data without deleting saved bundles.
- Load Investigation Bundle is either implemented and validated or clearly marked as not included in 0.1.
- No `data/`, `logs/`, real bundles, local SQLite DBs, or ad hoc build artifacts are committed.

## Current 0.1 Readiness

Thoth currently builds as standalone binaries and the web UI is not macOS-specific.

Not ready to commit binaries until:

- release packaging script exists
- Linux amd64 runtime validation is completed
- release docs and checksums are generated
- Load Investigation Bundle scope is either implemented or explicitly deferred in `VALIDATION.md`
- the release can be tested from a normal Linux VM without a custom Thoth VM image

## Release Label

Use:

```text
Thoth 0.1 student test build
```

Do not call this Thoth 1.0. The current product is useful for supervised testing but still early.
