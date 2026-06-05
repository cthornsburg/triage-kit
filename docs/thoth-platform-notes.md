# Thoth Platform Notes

## Role

**Thoth** is the analyst-side review and triage environment for bundles collected by **SEKER**.

Its job is to:
- ingest collected bundles
- validate manifests and hashes
- normalize artifacts
- flag suspicious conditions
- support analyst review and reporting

It should **not** behave like a casual desktop app that blindly opens whatever came off a suspect endpoint.

## Platform direction

Recommended direction:
- run Thoth on **macOS or Linux**
- prefer a **lightweight Linux VM** as the actual analysis workspace
- use the laptop host as the operator platform, not the trust boundary

The current Thoth web UI is not macOS-specific. It is a local Go HTTP service backed by SQLite and filesystem storage. macOS is the active development path; Linux amd64 should be treated as the preferred VM validation target before committing a packaged Thoth executable.

For Thoth 0.1, do not distribute a baseline VM image. Build and validate Thoth as a portable app package first, then document how to run it inside a normal Linux VM. NighHax VM can become optional guidance or a future profile after that repo is cleaned up, but it should not be required for the initial preview build.

## Why not run Thoth directly on the same general-purpose workstation without isolation?

Because deeper triage and forensic review always carries some risk:
- accidental opening of hostile files
- malicious document payloads
- browser-based preview risk
- unsafe tooling behavior
- analyst mistakes under time pressure

A small Linux VM gives you a better place to contain mistakes.

## Recommended architecture

### Host device
A laptop used by the mobile response team.

Host OS can be:
- macOS, or
- Linux

Host responsibilities:
- carry the analyst workflow
- manage storage and transport
- host the Thoth VM
- keep external communications, note-taking, and case coordination outside the analysis VM when appropriate

### Thoth analysis VM
Preferred shape:
- small Linux VM
- snapshot-friendly
- minimal services
- no day-to-day personal use
- purpose-built for triage and review

VM responsibilities:
- ingest SEKER bundles
- run parsing/normalization tools
- review text/CSV/JSON artifacts
- optionally run deeper offline tools on copied artifacts

## Security stance

### Core rule
Treat every SEKER bundle as **untrusted input**.

### Baseline handling rules
- do not execute binaries from collected systems
- do not open suspicious artifacts on the host OS by accident
- avoid auto-mount/auto-open behavior where possible
- prefer copying bundles into the VM through a controlled workflow
- keep the analysis VM disposable and easy to revert

### Good operational habits
- snapshot before deeper review
- mount collected media read-only when possible
- unpack into a dedicated case workspace
- use separate tooling for preview vs deeper analysis
- keep internet access intentional, not ambient
- export findings out; do not casually move suspect artifacts around the host

## Suggested VM profile

Nice baseline for Thoth VM:
- lightweight Linux distro
- snapshots enabled
- limited background services
- enough disk for bundle storage and case notes
- preloaded text/JSON/CSV tooling
- optional forensic helpers added deliberately, not by default clutter

## Tooling philosophy

Start lean.

Core Thoth v1 can work with:
- manifest/hash validation
- bundle browser
- artifact normalization
- rule-based triage
- case notes and disposition
- report export

Additional forensic tools can be layered in later, but the VM should stay understandable and reproducible.

## Mobile response team model

The most practical field shape is:
- **SEKER** on USB for first-touch collection by less trained IT staff
- **Thoth** on a response laptop for analyst review
- lightweight Linux VM on that laptop for controlled triage and deeper inspection

That gives you:
- lower training burden at the endpoint
- a safer place for analyst work
- portability for field response
- a clean story for scaling beyond one person

## Recommendation

For planning purposes, assume:
- **SEKER** = Windows-first collector on removable media
- **Thoth** = Linux-VM-centered analysis workflow running on a macOS or Linux laptop

That is a much cleaner architecture than trying to make the collector also be the review station.
