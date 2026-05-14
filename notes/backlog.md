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
