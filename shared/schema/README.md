# Schema Drafts

These schemas define the contract between the USB collector and the Thoth analysis hub.

## Why this exists

Without a schema:
- collector output drifts over time
- hub parsers become brittle
- one-off artifacts break ingest
- multi-system collection gets messy fast

## Core schema set

- `collector-bundle-manifest.schema.json` — per-system case bundle
- `artifact-record.schema.json` — one collected artifact entry
- `batch-manifest.schema.json` — one USB session containing multiple collected systems

## Design note

The collector should be able to gather from **multiple systems before returning to the hub**.
That means we need both:
- a per-system bundle manifest
- a top-level batch manifest for the USB/session itself
