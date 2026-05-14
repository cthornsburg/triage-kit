# Architecture

## Summary

Use a **two-tier design**:

- **Tier 1: USB collector** for low-skill operators on suspect endpoints
- **Tier 2: Thoth analysis hub** for experienced reviewers in a safer environment

This keeps endpoint interaction simple and keeps interpretation centralized.

## Why this fits your use case

You want:
- limited user engagement
- collection by lightly trained staff
- no installation if possible
- no elevation if possible
- a central place to review findings

That points to a portable collector plus a normalized ingest/review pipeline.

## Recommendation on stack

### SEKER
**Primary recommendation: Go**

Why:
- easy to ship as a single binary
- good cross-compilation story
- low runtime dependency pain
- straightforward filesystem/process/command orchestration
- easier USB distribution than Python/Node-heavy packaging

Suggested pattern:
- Go binary orchestrates collection steps
- platform adapters hide OS-specific commands
- output written as a signed or checksummed case bundle

### Thoth analysis hub
Two reasonable options:

1. **Go-first hub**
   - same language across collector and hub
   - simpler deployment story
   - good fit if you want a lightweight local API + CLI

2. **Go collector + Python hub**
   - better analysis ecosystem for parsing, enrichment, notebooks, and reporting
   - slightly messier deployment

My recommendation:
- start **Go for collector**
- keep hub language flexible until the schema stabilizes
- do **not** force an opencode dependency into the architecture right now

## Tier 1 — USB Collector

### Primary job
Collect a predictable, bounded triage package with near-zero operator judgment.

### UX model
- operator inserts USB
- launches one obvious executable/script
- answers only a few prompts at most:
  - case ID
  - site/asset label
  - optional notes
- waits for completion
- removes USB and hands it off

### SEKER output goals
- timestamped case folder
- manifest file
- machine summary
- evidence bundle
- operator log
- integrity hashes

### Good first-release collection targets
- host identity
- current user context
- system time / timezone
- OS version / build
- running processes
- services/tasks where readable
- network adapters, IPs, routes, DNS
- active network connections
- startup persistence reachable without admin
- recent files / temp / downloads triage
- security tooling presence
- basic browser/process indicators where readable
- event/log exports that user context can access

### Explicit non-goals for v1
- memory acquisition
- disk imaging
- privileged registry/database extraction
- deep EDR bypass tricks
- stealth collection

## Tier 2 — Analysis Hub

### Primary job
Ingest bundles, normalize artifacts, score findings, and guide human review.

### Core components
- **ingest** — validate bundle, unpack, hash, register case
- **normalize** — convert raw artifacts into stable records
- **scoring** — rules that highlight suspicious conditions
- **review** — analyst CLI/API/UI for findings and notes
- **reporting** — export a short triage summary and detailed evidence notes

### Suggested workflow
1. analyst imports bundle
2. hub validates manifest and hashes
3. hub normalizes artifacts into common records
4. rules flag issues for review
5. analyst marks findings / notes / severity
6. hub exports summary for follow-up or escalation

## Shared contract

The collector and hub should agree on:
- bundle layout
- manifest schema
- artifact naming
- timestamp format
- host metadata schema
- rule input schema
- review output schema

That contract belongs in `shared/schema/` and `shared/contracts/`.

## Security / trust model

- treat collector output as untrusted input
- never execute artifacts from a suspect host during ingest
- default the hub to offline/local-first review where possible
- keep enrichment optional and explicit
- hash everything on collection and re-verify on ingest

## Opencode view

I would keep opencode out of the initial architecture.

It may be useful later as:
- a coding environment preference
- a helper for rapid internal prototyping
- a separate developer convenience layer

It should **not** be a dependency of the collection or review design.

## Coding note

I do not need a special skill to write Go here.
I can write Go directly, and if we want, I can also spin up a coding sub-agent later for implementation slices.
