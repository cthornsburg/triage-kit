# Thoth Analyst Workflow

## Goal

Give the analyst a repeatable path from **USB received** to **triage decision made** without improvising every case.

## Workflow summary

1. receive SEKER media
2. ingest bundle(s) into Thoth
3. validate integrity
4. create analyst case workspace
5. review dashboard summary
6. drill into flagged artifacts
7. record findings and disposition
8. export summary
9. optionally reset and reload the SEKER USB for reuse

## Step 1 — Receive response media

Analyst actions:
- identify the SEKER USB/device
- confirm expected label and approximate size
- note whether it may contain multiple collected systems

Principle:
- treat media as untrusted from the start

## Step 2 — Ingest

Thoth should:
- detect the SEKER batch structure automatically
- enumerate cases found on the media
- show a pre-ingest summary before copying

Pre-ingest summary should include:
- batch id
- number of cases found
- case hostnames
- collection timestamps
- collector version

## Step 3 — Integrity validation

Thoth should validate before the analyst relies on the data.

Checks:
- required files exist
- manifest parses cleanly
- `hashes.sha256` verifies
- artifact paths match manifest entries
- errors/warnings are surfaced clearly

Possible states:
- valid
- valid with warnings
- incomplete / partial
- malformed / failed validation

## Step 4 — Create review workspace

Thoth should create a dedicated workspace per case inside the Linux VM.

Per-case workspace should contain:
- original imported bundle reference
- normalized artifacts
- findings
- analyst notes
- exportable summary data

## Step 5 — Dashboard first pass

Before deep inspection, the analyst should land on a concise dashboard.

The dashboard should answer:
- what host is this?
- when was it collected?
- did integrity checks pass?
- how many warnings/errors exist?
- what categories have notable findings?
- does this look routine or weird?

## Step 6 — Drill into findings

Analyst reviews:
- suspicious processes
- odd network connections
- persistence entries
- notable event log entries
- security posture gaps
- artifacts that failed collection or look incomplete

Thoth should let the analyst move from summary -> category -> artifact quickly.

## Step 7 — Record assessment

The analyst should be able to capture:
- freeform notes
- finding severity
- confidence
- recommended next step
- case disposition

Suggested dispositions:
- benign / expected
- monitor
- remediation needed
- escalate for deeper review
- containment recommended

## Step 8 — Export summary

Thoth should export a compact review package that includes:
- case metadata
- integrity results
- key findings
- analyst notes
- disposition

## Step 9 — Reprepare SEKER media

After successful ingest and verification, Thoth may offer:
- wipe/reformat SEKER media
- reload fresh collector payload
- restore operator instructions
- relabel media if desired

This should require explicit confirmation.

## Design requirement

The workflow should optimize for:
- speed
- clarity
- repeatability
- analyst safety
- low cognitive load under pressure

## Recommendation

Thoth should feel less like a raw toolkit and more like a guided triage lane:
- ingest
- validate
- summarize
- investigate
- decide
- export
- reset media
