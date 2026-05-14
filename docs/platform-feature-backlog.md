# Platform Feature Backlog

Cross-cutting platform features for the Thoth analyst environment that do not belong only to SEKER collection or only to one artifact page.

This file is for analyst-platform capabilities, environment helpers, and operational enrichments that make the review workstation more useful.

## Current environment stance

- current primary host: macOS
- likely future deployment option: portable or semi-portable VM-based analyst environment
- design goal: keep the analyst workflow portable without forcing hard dependency on one workstation setup

## Priority backlog

### 1. Quick IOC enrichment actions

Add fast analyst actions for common pivots from within the UI.

Examples:
- search for an IP across the current case
- copy IP / domain / hash quickly
- open a safe external enrichment action for an indicator when the environment allows it

Why:
- analysts often need to pivot immediately on a suspicious IP, domain, or hash
- this is platform behavior, not just one page's display problem

### 2. Quick IP geolocation link or helper

If Thoth moves into a VM or more self-contained analyst environment, add a quick IP geolocation capability.

Desired behavior:
- click or action from an IP value in the UI
- open a geolocation lookup or run a local helper
- return country/region/ASN/provider context fast enough to support first-pass triage

Notes:
- this can start as a simple outbound link if the environment allows browser/network access
- later it could become a bundled helper/tool inside the VM
- geolocation should be treated as context, not attribution

### 3. Portable analyst-tool bundle

If Thoth is packaged for VM use, define a small bundled analyst toolkit for common lookups.

Candidates:
- IP geolocation
- ASN lookup
- whois/RDAP helper
- hash reputation pivot hooks
- local note/export helpers

Why:
- the analyst experience gets much better when routine pivots do not require leaving the platform or hand-copying values everywhere

### 4. Environment-aware external actions

Platform should understand whether it is running:
- on a local macOS workstation
- in a more locked-down VM
- in an offline or low-connectivity environment

Why:
- some helpful actions are fine on a connected workstation but unavailable or undesirable in an isolated VM
- UI should degrade honestly instead of showing dead buttons

### 5. Safe external-enrichment policy

Before adding one-click external pivots broadly, define:
- what can leave the box
- when the analyst should confirm before opening/pivoting
- whether private IPs, internal hostnames, or sensitive case metadata should be blocked from external actions

Why:
- enrichment is useful, but accidental data leakage would be dumb

## Suggested implementation order

1. local IOC search inside Thoth
2. clickable IP action model in the UI
3. basic geolocation link/helper for VM-friendly use
4. broader enrichment helpers (ASN, whois/RDAP, hash pivots)
5. environment-aware policy/controls for online vs offline analyst deployments

## Relationship to product backlog

- SEKER backlog = what the collector gathers
- Thoth backlog = how case data is normalized, displayed, and reviewed
- platform feature backlog = analyst-environment capabilities and cross-cutting helpers around the review workflow
