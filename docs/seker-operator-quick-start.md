# SEKER Operator Quick Start

This guide is for a student or field operator running **SEKER** on a Windows lab endpoint and handing the collection to a Thoth analyst.

SEKER is a rapid triage collector. It is not full forensic acquisition, memory capture, credential collection, or broad user-file triage.

## Before You Start

Use SEKER only on:

- lab systems
- synthetic training images
- endpoints where you have explicit authorization

Do not run SEKER on personal, production, or real incident systems for public coursework unless the data-handling plan has been approved by an instructor or maintainer.

## Prepare The Collector

For lab testing, use the checked-in Windows release binary:

```text
releases/seker/1.0/seker.exe
```

Copy `seker.exe` to a removable drive or a writable test folder.

Optional checksum check on Windows:

```powershell
certutil -hashfile .\seker.exe SHA256
```

Expected SHA-256:

```text
ab024f6636e3e8c6d518d9d363eff2d2cd65cbe61a6ae7a4f7e32c9e7fb2a331
```

## Run SEKER

Open PowerShell in the folder that contains `seker.exe`.

Recommended lab run:

```powershell
.\seker.exe --output-dir . --hostname LAB-WS-01 --operator-id student01 --media-label SEKER-LAB
```

Useful flags:

- `--output-dir` — where SEKER writes the `collections/` folder
- `--hostname` — operator-facing host label for the collection
- `--operator-id` — student/operator label
- `--media-label` — removable-media or lab-run label
- `--batch-id` — optional batch ID; SEKER generates one if omitted
- `--notes` — optional short operator notes

SEKER is designed for no-install, no-admin baseline triage. Some artifacts may be partial or unavailable without elevation; that should appear in the manifest, errors, and collector log.

## Expected Output

SEKER writes a batch under:

```text
collections/<batch-id>/
  batch-manifest.json
  case-<host>-<timestamp>/
    manifest.json
    hashes.sha256
    collector-log.txt
    errors.json
    host/
    processes/
    network/
    logs/
    persistence/
    security/
    software/
    devices/
```

Keep the whole `collections/` folder together. Do not rename or edit collected files before Thoth ingest.

## Hand Off To Thoth

After the run:

1. Confirm `collections/<batch-id>/batch-manifest.json` exists.
2. Confirm the case folder contains `manifest.json` and `hashes.sha256`.
3. Safely eject the removable drive, or copy the full `collections/` folder to the analyst machine.
4. Give the analyst the source path for Thoth ingest.

For the analyst side, use `docs/thoth-analyst-quick-start.md`.

## Troubleshooting

- If SEKER cannot write output, rerun from a writable folder or removable drive.
- If antivirus warns on the executable, stop and ask the instructor or maintainer before bypassing controls.
- If a command is blocked or unavailable, keep the partial bundle; Thoth can still ingest partial collections.
- If PowerShell closes too quickly, open PowerShell first, then run `.\seker.exe ...` from that window.
- If you need to repeat a lab run, use a new `--batch-id` or a clean output folder.

## Do Not Commit

Do not commit real SEKER collection output. Only synthetic, redacted sample bundles belong in the repository.
