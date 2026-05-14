# Thoth v1 Features

## Purpose

**Thoth v1** is the first analyst-side triage environment for bundles collected by **SEKER**.

It is meant to help an analyst on a macOS or Linux laptop quickly ingest, review, and disposition field collections without turning the analyst workflow into a pile of ad hoc scripts.

## Operating model

Assumed workflow:
- lesser-trained IT staff use **SEKER** on Windows endpoints
- an analyst uses **Thoth** to ingest and review the resulting bundles
- Thoth runs in a **nimble Linux VM** on a response laptop
- the laptop + VM combination functions as a mobile response kit

## V1 feature set

### 1. Bundle ingest
Thoth should:
- import one or more SEKER case bundles from response media
- detect batch structure automatically
- register each case as a separate review item
- preserve original collected metadata

### 2. Integrity validation
Thoth should:
- validate manifest structure
- verify file presence against the manifest
- verify hashes from `hashes.sha256`
- flag missing, altered, or malformed artifacts

This is table-stakes for trusting what was collected.

### 3. Safe case workspace creation
Thoth should:
- copy or stage bundles into a dedicated case workspace inside the analysis VM
- keep the original collected media separate from the active review workspace
- treat all imported content as untrusted input

### 4. Case overview
For each case, Thoth should show at least:
- hostname
- collected time
- collector version
- batch id
- case id
- artifact count
- warnings count
- errors count
- collection status

This gives the analyst a fast first read.

### 5. Artifact browser
Thoth should provide a simple way to inspect collected artifacts by category:
- host
- processes
- network
- persistence
- logs
- security
- files
- devices

V1 does not need to be fancy. A clean structured browser is enough.

### 6. Normalized triage views
Thoth should normalize the most useful baseline artifacts into analyst-friendly views where practical.

Good v1 candidates:
- process list
- active network connections
- autoruns / persistence entries
- recent event log highlights
- scheduled tasks
- host identity and OS context

### 7. Rule-based findings
Thoth v1 should support lightweight detection logic such as:
- suspicious process names or locations
- unsigned or user-profile autoruns when visible in the data
- unusual outbound connections
- encoded PowerShell indicators in logs or command text when available
- notable Windows Defender or PowerShell operational events

This should start simple and explain why something was flagged.

### 8. Analyst notes and disposition
Thoth should let the analyst record:
- notes
- severity / priority
- disposition
- next action

Suggested disposition states:
- benign / expected
- needs follow-up
- escalate to deeper review
- containment recommended

### 9. Report export
Thoth should export a concise case summary including:
- basic case metadata
- findings
- analyst notes
- disposition
- integrity-validation status

### 10. Multi-case handling
Because a single SEKER USB may contain multiple systems, Thoth should:
- ingest many cases from one batch
- preserve case-to-batch relationships
- allow analysts to compare cases from the same event or field run

## Explicit non-goals for v1

Thoth v1 does not need to be:
- a full forensic suite
- an EDR replacement
- a malware sandbox
- an endpoint live-response agent
- an automated incident commander

The goal is a disciplined triage hub.

## Linux VM tool posture

The Linux VM should stay lean.

Good baseline tooling:
- Python
- jq
- ripgrep
- SQLite
- hash utilities
- JSON/CSV/text viewers
- a small number of carefully chosen forensic helpers

Add deeper tools deliberately, not as kitchen-sink clutter.

## Deferred from v1

Keep out of the initial v1 scope:
- analyst-driven SEKER USB wipe/reset/reload

It is feasible, but destructive enough that it belongs in the backlog until Thoth ingest, integrity validation, and analyst workflow are stable.
