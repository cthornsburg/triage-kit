# Mobile Response Workflow

## Roles

### Lesser-trained IT operator
Uses **SEKER** to collect a bounded triage package from a suspect endpoint.

Primary responsibilities:
- insert approved USB
- run `seker.exe`
- wait for completion
- label the collection if prompted
- return the USB or copied bundle to the analyst

### Analyst
Uses **Thoth** to triage and review the collected data.

Primary responsibilities:
- ingest the SEKER bundle
- validate hashes and manifest
- review findings and anomalies
- decide whether escalation or deeper forensic work is needed

## Workflow

### Step 1 — Field collection
- operator runs SEKER on the suspect Windows system
- SEKER writes a case bundle back to the response media
- multiple systems can be collected before returning to the analyst, if needed

### Step 2 — Controlled transfer
- analyst receives the response media
- bundle is transferred into the Thoth analysis VM using a controlled process
- original collected media is preserved when practical

### Step 3 — Ingest
- Thoth validates the batch/case manifest
- Thoth verifies hashes
- Thoth registers each case separately, even when multiple cases came from one USB batch

### Step 4 — Triage
- Thoth highlights:
  - suspicious processes
  - interesting network state
  - persistence footholds
  - notable logs
  - missing or weak controls

### Step 5 — Review and disposition
- analyst marks findings
- analyst adds notes
- analyst decides:
  - no further action
  - remediation guidance
  - escalation to deeper forensic workflow
  - containment / incident declaration

## Design principles

- keep collection simple
- keep analysis centralized
- treat collected data as untrusted
- prefer structured outputs over ad hoc notes
- make the laptop + VM combination the mobile response kit

## Future-friendly extensions

Later, Thoth could add:
- richer parsers
- artifact search across cases
- case comparison across multiple hosts from the same event
- deeper forensic plugins/tools in the VM
- exportable reports for incident documentation
- SEKER media reset/reload after successful ingest and verification

## Recommendation

Build around this operating assumption:
- **SEKER** is what the field operator touches
- **Thoth** is what the analyst trusts enough to review inside a contained VM workflow

That split is what keeps the workflow teachable and scalable.
