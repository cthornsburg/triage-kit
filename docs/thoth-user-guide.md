# Thoth User Guide

Draft user-facing guide for analysts reviewing SEKER collections in Thoth.

## Purpose

Thoth turns one or more SEKER endpoint collections into a structured analyst review workflow. The goal is not to replace a full forensic acquisition. The goal is fast, repeatable triage: understand the host, identify likely suspicious activity, record disposition, and decide what should happen next.

## Core workflow

1. Receive SEKER media or a copied SEKER batch folder.
2. Ingest the batch into Thoth.
3. Assign or select the analyst-facing case/incident name.
4. Review Host Overview, processes, network state, persistence, tasks, logs, and findings.
5. Use search/pivots to follow indicators across artifacts.
6. Record notes and disposition.
7. Export a report or next-action summary.

## Case and device grouping

A SEKER bundle represents collection from an endpoint. A Thoth analyst case or incident may eventually contain more than one endpoint.

During ingest, Thoth should support two paths:

- **Attach to existing case/incident:** choose an existing analyst case from a dropdown when a new device belongs to an already-open event.
- **Create a new case/incident:** manually enter a new analyst case name when the device starts a new investigation.

Why this matters:

- multi-device incidents need correlation across hosts
- analysts should not depend on collector-side `case_id` values
- grouping should happen at intake, not after data is scattered across unrelated records

## Artifact review guide

### Host Overview

Use Host Overview first to answer:

- What machine is this?
- Who was logged in or collecting?
- What OS/build is it running?
- What network, software, and host-level context is visible?
- When was it collected?
- Does the time zone or boot time affect interpretation?

Current Thoth behavior:

- the main case page links to **Open Host Overview**
- Host Overview presents host identity in readable fields instead of requiring analysts to parse raw JSON first
- the Network Configuration drilldown shows readable adapter/global IP configuration cards
- the old `/host-context` route may still work for compatibility, but user-facing docs and navigation should use **Host Overview**

Why it matters:

- establishes scope and timeline
- helps avoid mixing up similarly named endpoints
- supports patch-posture and environment interpretation

Future improvement:

- continue expanding Host Overview as the landing area for host-level context: network configuration, installed-program inventory, Defender/Firewall posture, patch posture, current and previously seen USB/removable-device context, Wi-Fi/Bluetooth context, and device/virtual adapter clues
- installed-program inventory should help analysts quickly compare endpoint software against an approved baseline and spot unexpected remote-access, admin, dual-use, or security-tool changes
- the network/ipconfig drilldown should stay analyst-friendly and avoid sending users straight to raw JSON

### Normalized artifact sets and collected source preview

The main case page includes a **Normalized artifact sets** table. This table tells analysts which SEKER source artifacts were collected and normalized into Thoth.

Current Thoth behavior:

- artifact-set counts represent records collected into the SEKER bundle and normalized by Thoth, not the full endpoint history
- the **source** column shows the collected source artifact path from the SEKER bundle, such as `logs/system-events.txt`, `processes/process-list.csv`, or `persistence/hkcu-run.txt`
- source paths link to a collected-source preview at `/cases/{case_uuid}/source/{artifact_key}`
- collected-source preview pages show both:
  - the bundle-relative collected source path
  - the local imported copy path inside Thoth storage
- large source previews may be truncated for browser safety; use the local imported copy path if the full file is needed

Why it matters:

- analysts should see where evidence came from on the collected machine/bundle, not only Thoth's internal storage path
- source previews provide a fast fallback when a friendly view omits a field or parsing looks suspicious

### Process List

Use the Process List to look for suspicious or unexpected execution.

Important fields:

- **Process/Name:** executable or process name
- **PID / PPID:** process identity and parent relationship, where available
- **User:** account context
- **Session:** whether the process appears interactive or service/background
- **Command Path:** executable path and command line, where SEKER can collect it
- **Window title:** useful for some interactive programs, but not enough by itself

Why it matters:

- malware and living-off-the-land activity often appears first as odd process names, locations, parentage, or command lines
- user-context execution from Downloads, Temp, AppData, scripts, or unusual paths deserves fast review

Expected search behavior:

- search should support case-insensitive partial matches by default
- analysts should be able to search fragments of process names, users, paths, command lines, or PIDs

SEKER dependency:

- current early collection may rely on `tasklist /fo csv /v`, which does not include full command line, executable path, or PPID
- future SEKER collection should attempt WMI/CIM process detail collection and fall back gracefully when permissions limit fields

### Scheduled Tasks

Use Scheduled Tasks to review persistence and recurring execution.

Important fields:

- task name
- command/action
- trigger
- run-as account
- enabled/hidden state
- last run time
- next run time
- start time
- created/modified timestamps where available

Why it matters:

- scheduled tasks are a common persistence and execution mechanism
- recent or unusual task creation can explain recurring payload launch
- run-as account and timing help distinguish normal maintenance from suspicious automation

Needed UX:

- sort and filter by dates/times, especially last run, next run, start time, and created/modified timestamps where available

Current Thoth behavior:

- Scheduled Tasks has a friendly page with search/filter controls
- last run, next run, and start time sorting parse common Windows task time formats instead of doing plain string sort
- finding evidence can link to exact scheduled-task record anchors when the rule engine provides a record index

### Network State

Use Network views to identify active connections, listening services, routing/DNS oddities, and IOC pivots.

Important fields:

- local and remote IP/port
- protocol
- connection state
- PID/process mapping where available
- DNS servers and gateway configuration
- route table entries

Why it matters:

- suspicious outbound connections may indicate beaconing or data movement
- unexpected listening ports can indicate exposed services or backdoors
- DNS/gateway/routing anomalies can explain traffic redirection or containment issues

Needed UX:

- filter by state, protocol, IP, port, service label, and process
- sort/filter by remote address so external connections are easy to group and review
- provide an external-only/public-remote pivot that hides loopback, local, private RFC1918, multicast, and unspecified addresses by default
- make PID/process values clickable so analysts can jump back to the process page filtered to that PID for additional context
- support partial matching for fast IOC pivots

Current Thoth behavior:

- Network State supports protocol/state/search filters and a public-remote pivot for remote IP review
- remote IPs can be used as pivots
- PID/process values link back to the Process page filtered to that PID where available

### Logs

Use logs to confirm timing, errors, script execution, service changes, and security-tool clues.

Recommended navigation:

- main case page should link to a **System Logs** landing page
- System Logs should link to each individual log with a short hint about what the log contains and when to use it

Current Thoth behavior:

- the main case page links to a **System Logs** landing page rather than listing every individual log source directly
- each log card explains the intended use of Application, System, PowerShell Operational, and Defender Operational logs
- individual log pages include search, level filtering, and Event ID filtering
- search and filters run across the full loaded log record set before pagination
- event IDs display whenever present
- records near the SEKER collection time can show visible collection self-noise hints instead of being hidden

Priority log views:

- Application — application crashes, installer/service errors, and app-level clues
- System — service, driver, boot, device, and OS-level activity
- PowerShell Operational — script execution and PowerShell activity clues
- Defender Operational — Microsoft Defender detections, remediation, exclusions, and security-tool context

Why it matters:

- logs provide timeline context around process/network/persistence artifacts
- PowerShell logs can reveal script execution
- Defender logs may show detections, exclusions, or remediation activity

SEKER collection scope and self-noise:

- Log counts in Thoth are counts of records collected into the SEKER bundle, not the endpoint's full historical Windows Event Log size.
- Current SEKER builds collect a recent bounded slice per log source; older bundles may contain only the most recent 100 events per log. Analysts should not interpret `100 collected records` as `100 total records on the endpoint`.
- Events with timestamps that closely match the SEKER collection time are often generated by SEKER itself, especially PowerShell startup/ready events and other collection-command traces.
- Treat these as likely collection self-noise when the timing lines up, but do not suppress them by default. Analysts should still be able to see and evaluate the records in context.
- Thoth should use visible colored hints for collection scope and events near collection time rather than hiding records.

Needed UX:

- event cards should show timestamp, provider/channel, event ID, level, user, and a readable summary
- event ID codes should display whenever present across all log views because they are high-value IR search/pivot fields
- log search/filtering should run across the full log record set before pagination, with filtered count shown separately from total count
- PowerShell 4104/script-block events should display the captured script block or command excerpt prominently; showing only Event ID 4104 + Warning is scary but not actionable
- raw event records should remain available only as secondary detail

### Persistence Artifacts

Use persistence views to identify mechanisms that launch code after reboot or login.

Important sources:

- HKCU Run / RunOnce
- Startup folder entries
- scheduled tasks
- services where readable
- user-space autorun locations

Current Thoth behavior:

- the main case page links to a friendly **Persistence** view
- the Persistence view currently combines HKCU Run, HKCU RunOnce, and Startup Folder entries into analyst-friendly cards
- analysts can search by name, command/path, registry path, source, and review hint text
- user-writable paths are visibly called out because they are common no-admin persistence locations
- raw artifact fallback links remain available for HKCU Run, HKCU RunOnce, and Startup Folder source records
- persistence findings can link directly to the relevant Persistence record anchor when the rule engine provides a record index

Why it matters:

- persistence artifacts explain how suspicious activity survives reboot or user login
- user-writable persistence locations are especially important in no-admin compromise scenarios

### Findings

Findings are first-pass review aids, not final conclusions.

Use them to answer:

- What should I inspect first?
- Why did Thoth flag this?
- What evidence supports the finding?
- Is this suspicious, benign, or needs follow-up?

Why it matters:

- analysts need explainable signals, not opaque scoring
- suppressed known-good noise should remain reviewable but not dominate the default view

Needed UX:

- show the source artifact/log identity behind each finding
- make finding evidence clickable so analysts can jump to the specific filtered artifact/log view or record set that triggered the finding; for example, a PowerShell 4104 finding should link to the PowerShell log filtered to the suspect 4104 records
- support analyst disposition and suppression/rule tuning

Current Thoth behavior:

- findings show cleaner source labels instead of raw internal evidence strings
- PowerShell 4104 findings link to the PowerShell log filtered to Event ID 4104
- scheduled-task findings link to exact scheduled-task records where available
- persistence findings link to exact Persistence view records where available
- analyst disposition and notes are still pending

## Common triage use cases

### 1. Suspicious process reported by help desk

1. Open the affected host.
2. Search Process List for partial process name or PID.
3. Review Command Path, user, session, and window/title context.
4. Pivot to network connections by PID or process name.
5. Check scheduled tasks and persistence for matching command/path fragments.
6. Review logs near the observed execution time.

### 2. Known bad IP or domain

1. Search Network State for the IP, partial IP, port, or service.
2. Identify PID/process mapping where available.
3. Search logs and PowerShell entries for the same indicator.
4. If multi-device case grouping exists, search across all devices in the analyst case.
5. Record whether the indicator is confirmed, false positive, or needs deeper acquisition.

### 3. Possible persistence

1. Review Scheduled Tasks sorted by recent dates.
2. Review Run/RunOnce and Startup folder entries.
3. Search for suspicious command/path fragments across process and persistence views.
4. Check logs around creation or execution time.
5. Mark disposition and recommended containment/removal steps.

### 4. Multi-device incident

1. During ingest, attach each endpoint bundle to the same analyst case/incident.
2. Search across devices for shared IPs, process names, users, hashes, domains, or command fragments.
3. Compare Host Overview context and timeline differences.
4. Use shared indicators to prioritize which hosts need deeper review.

## Reporting expectations

A useful Thoth report should include:

- analyst case/incident name
- devices reviewed
- collection timestamps
- key findings and disposition
- supporting evidence paths/artifacts
- limitations caused by no-admin collection
- recommended next actions

## Limitations to explain to users

SEKER baseline collection is no-install and no-admin. That is useful for fast triage, but it means some data may be incomplete:

- protected processes may hide command/path details
- Security logs may not be readable
- some EDR/security product data may be inaccessible
- memory capture is out of scope for baseline mode
- absence of evidence in Thoth is not proof of absence on the host

The right phrasing is: **rapid triage and decision support**, not full forensic completeness.
