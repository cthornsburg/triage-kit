# Contributing

Thanks for helping improve **Incident Response Kit**.

## Principles

- Keep tooling portable, boring, and auditable.
- Prefer small, reviewable changes with clear test output.
- Preserve the baseline promise: no install and no admin requirement for SEKER baseline triage.
- Be explicit about collection limits; this is rapid triage, not full forensic acquisition.
- This repo is public: do not add sensitive data, real incident data, credentials, private IPs, or customer-specific artifacts.

## What to contribute

- Collector improvements that preserve predictable bundle output
- Thoth ingest/normalization/UI improvements
- Schema, documentation, and packaging improvements
- Redacted sample bundles or synthetic test cases

## Safety rules

- Do not include real case data or unredacted endpoint artifacts.
- Do not add credential, browser-history, memory-capture, or elevated-collection behavior without an explicit design review.
- Do not add broad user-file triage to SEKER v1.x.
- If you find sensitive data, follow `SECURITY.md`.

## Workflow

1. Fork the repo.
2. Create a branch.
3. Run relevant tests:
   - `cd collector && go test ./...`
   - `cd hub && go test ./...`
4. Open a PR describing:
   - What changed
   - Why it helps
   - Validation performed
   - Any collection/safety implications

## Style

- Write for practitioners: clear headings, checklists, and explicit assumptions.
- Keep generated/runtime artifacts out of commits unless they are intentionally redacted samples.
