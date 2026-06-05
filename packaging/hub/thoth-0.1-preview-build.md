# Thoth 0.1 Preview Build Plan

## Purpose

Create a public preview Thoth build without calling it a finished release.

Thoth 0.1 should let analysts, maintainers, instructors, learners, and contributors run the local review UI, ingest synthetic or lab SEKER bundles, record field decisions/notes, save or clear an investigation bundle, and exercise the current workflow without needing Go installed.

## Platform Target

Thoth is not macOS-specific. The web UI is a local Go HTTP server backed by SQLite and filesystem storage.

Supported test targets for 0.1:
- macOS arm64
- macOS amd64 if needed
- Linux amd64

Preferred analyst environment remains a lightweight Linux VM on a response laptop. The macOS build is useful for development and demos; Linux should be validated before calling the package preview-ready.

Do not target Windows for Thoth 0.1 unless a maintainer explicitly approves that scope. SEKER is Windows-first; Thoth is analyst-side review tooling.

## VM Scope Decision

Do not provide or maintain a baseline VM image for Thoth 0.1.

For the preview build, package Thoth from this repository first:
- build Linux and macOS binaries
- include release docs and checksums
- validate the Linux build inside a clean VM
- document how analysts and contributors can run Thoth inside a Linux VM

Keep the initial Thoth release focused and avoid maintaining a VM image, credentials, snapshots, guest additions, hypervisor quirks, and update drift before the app package itself is stable.

## Release Directory Shape

Generated preview package path:

```text
dist/thoth-0.1-preview/
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

Committed release binaries, if approved later, should live under `releases/thoth/0.1/` with the same documentation and checksum expectations.

Runtime-created mutable folders should not be committed:

```text
data/
logs/
tmp/
```

## Build Commands

Use the packaging script from the repository root:

```bash
packaging/hub/build-thoth.sh
```

The default output is `dist/thoth-0.1-preview/`.

## Preview Run Path

From the extracted Thoth release root:

```bash
export THOTH_ROOT="$PWD"
./scripts/run-thoth.sh
```

Then open:

```text
http://127.0.0.1:8080
```

Test with synthetic or approved lab bundles only. Do not use real endpoint data for public validation.

## 0.1 Validation Checklist

Before committing binaries:

- `scripts/check.sh` passes from repo root.
- Clean-clone build script produces binaries into `dist/thoth-0.1-preview/bin/`.
- `SHA256SUMS.txt` contains all generated binaries, scripts, and release docs.
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

Preview package status:

- release packaging script exists
- release docs and checksums are generated
- Linux amd64 runtime has been validated in a normal Linux VM
- Load Investigation Bundle remains outside the current preview package unless explicitly implemented and validated later
- student VM setup is documented in `docs/thoth-linux-vm-setup.md`

## Release Label

Use:

```text
Thoth 0.1 preview build
```

Do not call this Thoth 1.0. The current product is useful for supervised preview testing but still early.
