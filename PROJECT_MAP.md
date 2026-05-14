# PROJECT_MAP.md

- **Project:** Incident Response Kit
- **Status:** active prototype / SEKER 1.0 release-candidate staging
- **Audience:** maintainers, contributors, and public-sector security practitioners

## Purpose

Incident Response Kit is a two-tier incident-response toolkit:

1. **SEKER** — a low-touch Windows-first triage collector intended to run from removable media.
2. **Thoth** — an analyst review hub for ingesting SEKER bundles, normalizing artifacts, and reviewing findings.

## Start here

- `README.md` — project overview and design constraints
- `collector/README.md` — SEKER collector notes
- `hub/README.md` — Thoth ingest/review notes
- `docs/thoth-quick-start.md` — shortest operator path from SEKER media to Thoth review
- `docs/thoth-user-guide.md` — analyst guide and artifact-review workflow
- `docs/thoth-implementation-status.md` — current implemented state
- `docs/seker-next-iteration-plan.md` — SEKER collection roadmap
- `shared/contracts/bundle-layout.md` — collector-to-hub bundle contract
- `shared/schema/` — schema drafts

## Main areas

- `collector/` — endpoint-side SEKER collector code
- `hub/` — Thoth ingest, normalization, review API, and review CLI
- `shared/` — schemas and bundle contracts
- `docs/` — architecture, workflows, and operator guidance
- `packaging/` — packaging/release notes
- `samples/` — synthetic/redacted examples only
- `releases/` — current release-candidate metadata and binaries, when intentionally staged

## Working assumptions

- SEKER baseline should run from removable media with no installation.
- SEKER baseline should not require administrator privileges.
- Analysis should happen off-host in Thoth.
- Collection scope must stay honest: rapid triage, not full forensic acquisition.
- Real case data, secrets, private IPs, and unredacted endpoint artifacts do not belong in this public repo.

## Common commands

```bash
cd collector && go test ./...
cd hub && go test ./...
```

Build a Windows SEKER release candidate and archive any existing Desktop copy:

```bash
./scripts/build-seker-release.sh 1.0 rc1
```

## Common traps

- Do not promise forensic-complete collection without elevation.
- Do not couple the collector to network/cloud dependencies.
- Do not let analyst-centric complexity leak into the low-skill collector UX.
- Do not commit generated runtime data, real bundles, credentials, or unredacted endpoint artifacts.
