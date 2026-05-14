# Backlog

## Deferred ideas

### USB HID mode
Saved for later review.

Why deferred:
- adds hardware and operator complexity early
- changes the trust and execution model
- can blur the line between triage tooling and emulation/automation behavior
- not required to prove out the core two-tier collector + hub architecture

Revisit after:
1. baseline no-install collector exists
2. artifact bundle schema is stable
3. operator workflow has been tested

### Thoth-driven SEKER USB reset / reload
Saved for later review.

Why deferred:
- destructive action with real operator-error risk
- should not distract from core Thoth ingest/review flow
- needs strong device-identity and confirmation guardrails
- should come only after ingest/integrity workflow is stable

Revisit after:
1. Thoth ingest is working end-to-end
2. integrity validation is trustworthy
3. analyst workflow is stable
4. media-targeting UX is unambiguous

## Pre-push cleanup completed

- Removed SEKER `--case-id`, `CaseID`, `--dry-run`, and dry-run behavior.
- Kept `bundle_id` as SEKER collection identity.
- Kept `batch_id` for media/run grouping and generate it by default if not supplied.
- Thoth ingest no longer requires SEKER `case_id`.
- Thoth assigns or accepts analyst-facing Case ID at ingest.
- Thoth stores/displays SEKER `bundle_id` as Collection ID.
- Dedupe remains keyed on stable collection identity: `batch_id` + `bundle_id`.
- Labels/docs: Case ID = Thoth, Collection ID = SEKER bundle, Batch ID = SEKER grouping.


### SEKER items verified implemented

Verified against the current collector and Thoth normalization path on 2026-05-14:
- security posture collection and Thoth normalization/display
- installed-program inventory and Thoth normalization/display
- device/removable-media/current USB/previous USB evidence and Thoth normalization/display
- boot time / uptime host enrichment and Host Overview display
- richer process detail via CIM/WMI after log capture, with tasklist fallback
- Wi-Fi profile/interface metadata and Bluetooth PnP context collection
- virtual/container/VM/VPN adapter hints in Thoth network interpretation
