# Thoth Implementation Task Queue

Execution queue for contained implementation work on Thoth.

Operating mode:
- maintainers set priority and order
- one contained slice should be implemented at a time
- reviewers verify behavior and update backlog/docs after each slice
- do not mix unrelated UI refactors into the same ticket unless explicitly noted

## Locked priority workflow

### Tier 1 — analyst workflow blockers
Do these first.

1. case identity flow
   - Thoth owns analyst-facing case IDs
   - add ingest-time Case ID entry/override
   - stop depending on SEKER `case_id`
   - remove the current editable case-label field after the new flow exists

2. replace raw-JSON analyst pain
   - Host Overview
   - process list
   - scheduled tasks
   - logs
   - network
   - persistence

3. artifact/page usability
   - true record counts
   - pagination / load more
   - sorting/filtering
   - network state pivots
   - IOC search starting with IPs

### Tier 2 — analyst context and interpretation
4. evidence/source clarity
5. Host Overview enrichment
6. network enrichment, including remote-address filtering/sorting, external-only pivots, and PID/process drill-through links

### Tier 3 — complete review loop
7. notes + disposition
8. report export
9. dashboard improvements
10. suppressions / tunable controls

### Tier 4 — structural cleanup and scale-up
11. schema tightening
12. same-incident / same-analyst-case multi-device search and correlation, tied to ingest case assignment with an existing-case dropdown plus manual new case/incident entry
13. cross-case search/correlation
14. platform helpers and VM-friendly enrichment actions

## Immediate recommended execution order

1. Case ID at ingest
2. Notes/disposition
3. Report export
4. Findings suppressions / analyst-tunable controls
5. Dashboard improvements

Completed or substantially implemented:
- Host Overview page upgrade / visible Host Context rename
- Process list label/search cleanup
- Scheduled tasks analyst view and parsed time sorting for common fields
- System Logs landing page, Event ID filtering/display, full-log filtering before pagination, and collection self-noise hints
- Network filters, public-remote pivot, service labels, and PID/process links
- Friendly Persistence view for HKCU Run, HKCU RunOnce, and Startup Folder
- Finding evidence deep links for current PowerShell, scheduled-task, and persistence rule-engine findings
- Collected-source preview links from the main normalized artifact table

## Task queue

### GEO-THOTH-001 — Analyst-owned Case ID at ingest

Goal:
- move analyst-facing Case ID creation into Thoth ingest
- stop treating SEKER `case_id` as the visible analyst identifier

Scope:
- add ingest UI field for Case ID entry/override
- persist analyst Case ID in SQLite case record
- display analyst Case ID in case list/detail
- keep low-level collection identity separate from analyst case identity
- preserve bundle-based dedupe behavior

Out of scope:
- SEKER collector cleanup in the same ticket
- notes/disposition UI
- broad UI redesign

Acceptance checks:
- analyst can enter a Case ID during ingest
- imported case shows the analyst Case ID instead of relying on `CASE-LOCAL-001`
- duplicate-ingest protection still works
- no regression in current 5-case ingest flow

### GEO-THOTH-002 — Host Overview page upgrade

Status: substantially implemented; keep this ticket as historical context and for future Host Overview enrichment.

Goal:
- replace the current raw Host Identity JSON dump with a readable Host Overview summary

Scope:
- create analyst-friendly Host Overview page/card layout
- include hostname, OS/build, username/domain, collection time, boot/uptime if available
- reduce raw JSON as the default presentation
- keep raw/debug detail only as secondary/fallback if needed

Preferred extras if cheap:
- basic network summary linkage
- replace the Host Overview page's network ipconfig link with an analyst-friendly network configuration page/card instead of sending analysts to raw JSON
- placeholder section for patch posture

Out of scope:
- full patch posture implementation
- external enrichment

Acceptance checks:
- Host Overview page is readable without parsing JSON manually
- Host Overview network/ipconfig drilldown is readable without parsing JSON manually
- header duplication is reduced
- page still preserves the underlying normalized data path for later debugging if needed

### GEO-THOTH-003 — Process list view overhaul

Status: partially implemented; keep for richer process data once SEKER collects command path/PPID.

Goal:
- turn process list into an analyst-usable page with sort/search/filter

Scope:
- present process rows in a readable table/card view
- label the primary process-name column as "Process" or "Name" instead of analyst-unfriendly "Image"
- include process/name, PID, user, session, CPU time, window title, and any available command/path context; label that UI column "Command Path"
- add search/filter/sort for fast pivots
- make search use case-insensitive partial/substring matches by default, not exact-only matching

Preferred extras if cheap:
- PID-focused quick search
- suspicious path highlighting hooks for later findings work

Out of scope:
- scheduled-task redesign
- IOC search across all artifacts

Acceptance checks:
- analyst can sort/search the process list in the UI
- page is meaningfully more usable than raw JSON
- existing normalized process data still renders cleanly

### GEO-THOTH-004 — Scheduled tasks analyst view

Status: partially implemented; common last/next/start time sorting is implemented, modified/created timestamps remain source-data dependent.

Goal:
- redesign scheduled tasks into a high-signal persistence/execution page

Scope:
- show task name, action/command, trigger, run-as account, enabled/hidden state, and run timing where available
- add date/time sorting and filtering for scheduled task fields like last run, next run, start time, and modified/created time when available
- replace raw JSON as the default display

Acceptance checks:
- analyst can quickly spot suspicious task actions and triggers
- analyst can sort or filter scheduled tasks by relevant dates/times when those fields are available
- task timing/account context is visible without opening raw records

### GEO-THOTH-005 — Log views analyst format + record limits

Status: substantially implemented; keep for future log readability polish, especially richer PowerShell 4104 command/script-block prominence.

Goal:
- improve log readability and stop hiding record counts behind the current 100-row cap wording

Scope:
- add an intermediate **System Logs** landing page from the main case page instead of listing every log source directly on the case page
- include a short analyst hint/description next to each log-source link explaining what the next page contains and how it can be used
- event-oriented log display instead of raw JSON
- display event ID codes on all log pages whenever present because event IDs are high-value IR search/pivot fields
- true total counts
- make log search/filter operate across the full log record set before pagination, not only within the current 100-record page
- distinguish filtered count from total count when filters are active
- build level/event-ID dropdowns or filter options from the full relevant log set, not just the current page
- pagination or load more
- useful fields first: timestamp, event ID, provider/channel, level, summary/message

Acceptance checks:
- main case page links to a System Logs landing page rather than exposing all individual logs inline
- System Logs landing page describes Application, System, PowerShell, Defender, and future log sources clearly enough that analysts know which log to open first
- all log cards show Event ID when the source record includes one
- searching/filtering for an event ID such as PowerShell 4104 finds matching records anywhere in the log, not only records on the current page
- analyst can tell whether more than 100 records exist and whether the current view is filtered
- logs are readable without manual JSON inspection

## Ticket handling rules

- implement one ticket at a time
- update only the minimum docs/code needed for that ticket
- keep commits/scopes tight
- if a ticket reveals a bigger architectural blocker, stop and report it instead of freelancing a redesign
