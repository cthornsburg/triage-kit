# Thoth Dashboard Notes

## Purpose

The Thoth dashboard should give an analyst a fast first read on an ingested SEKER case without forcing them to manually open every artifact.

This is not a SOC wallboard. It is a **case triage dashboard**.

## Dashboard goals

The first screen should help the analyst answer:
- what machine is this?
- what was collected?
- did collection succeed cleanly?
- what looks suspicious first?
- where should I click next?

## V1 dashboard sections

### 1. Case header
Show:
- hostname
- case id
- batch id
- collected at
- collector version
- overall status
- artifact count
- warning count
- error count

### 2. Integrity card
Show:
- manifest valid / invalid
- hash verification pass/fail
- missing files count
- malformed entries count

This should be visually obvious. If integrity is weak, the analyst should know immediately.

### 3. Findings summary
Roll up counts by category, for example:
- processes flagged
- network connections flagged
- persistence items flagged
- notable logs flagged
- security gaps flagged

### 4. Collection coverage
Show what was actually gathered:
- host identity
- processes
- network
- persistence
- logs
- security
- files
- devices

If a category is missing or partial, show it plainly.

### 5. Key highlights
A small top-findings list such as:
- unusual process path
- suspicious autorun entry
- external network destination worth review
- PowerShell operational event worth opening
- Defender event worth review

The point is triage direction, not certainty theater.

### 6. Timeline / sequence hints
Useful if available from collected timestamps:
- bundle collected time
- artifact collection sequence
- notable event recency where parsed

### 7. Analyst work area
Dashboard should also surface:
- current disposition
- analyst notes snippet
- whether the case has been reviewed yet
- whether it has been escalated

## Interaction model

Recommended click path:
- dashboard -> finding category -> artifact detail -> notes/disposition

The analyst should not have to bounce between ten unrelated views.

## V1 implementation style

Keep it simple:
- static/local web UI or lightweight desktop shell is fine
- prioritize fast rendering from local JSON/CSV/text
- no need for a big backend at first

## Recommended V1 widgets

- case summary header
- integrity status card
- findings by category
- artifact coverage grid
- top findings list
- notes/disposition panel

## Non-goals

V1 dashboard does not need:
- real-time telemetry
- fleet-wide SOC views
- fancy graphs for their own sake
- ML scoring theater

## Recommendation

If Thoth gets one UX investment in v1, make it the dashboard.

That is what turns SEKER data into something an analyst can scan in minutes instead of spelunking through folders.
