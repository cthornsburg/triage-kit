# Bundle Layout Draft

## Multi-system USB layout

```text
usb-root/
  collector/
    seker.exe
    profiles/
      baseline-windows.yaml
  collections/
    batch-2026-05-09-01/
      batch-manifest.json
      case-hostA-2026-05-09T140500Z/
        manifest.json
        hashes.sha256
        collector-log.txt
        errors.json
        host/
        processes/
        network/
        persistence/
        files/
        security/
        logs/
        devices/
      case-hostB-2026-05-09T151700Z/
        manifest.json
        hashes.sha256
        collector-log.txt
        errors.json
        ...
```

## Model

- **batch** = one USB collection session that may contain multiple systems
- **case bundle** = one collected endpoint
- **artifact record** = one file or structured output inside a case bundle

## Why batch support matters

It lets an operator:
- triage multiple suspect hosts in the field
- come back once to the hub
- preserve a clean inventory of what was collected from which host and when

## Thoth ingest expectation

The hub should accept either:
1. a full batch directory, or
2. an individual case bundle

If a batch is ingested, the hub should register each contained case separately while preserving the shared batch metadata.
