# Thoth Low-Token Priority Queue

Prioritization for implementation while avoiding large token/rate-limit burn. Bias toward small, local UI fixes in `hub/cmd/review-api/main.go` and documentation updates. Defer schema-heavy, collector-heavy, and broad cross-case work.

## P0 — tiny UI wording / navigation fixes

These are low-risk, high-signal, and should be done first.

1. Rename Process List column labels — **done**
   - `Image` -> `Process`
   - `Window / path hint` -> `Command Path`
   - Reason: improves analyst clarity with tiny template-only change.

2. Add System Logs landing page shell — **done**
   - Added `/cases/{id}/logs`
   - Changed main case page to link to `System Logs`
   - Included short hints for Application, System, PowerShell, Defender.
   - Reason: resolves the half-finished log navigation without schema changes.

3. Make user-guide/doc links consistently open in a new tab where useful — **done for home-page user guide**
   - Home-page user guide link opens in a new tab.
   - Reason: small UX win.

## P1 — contained log-page correctness fixes

These directly address analyst trust and finding usefulness.

4. Fix log filtering before pagination — **done**
   - Load the relevant log records, filter/search in memory, then paginate the filtered list.
   - Show `filtered of total` count when filters are active.
   - Reason: makes `4104` and finding evidence links reliable.
   - Scope guardrail: in-memory is acceptable for current prototype volumes; avoid DB query redesign for now.

5. Add Event ID filter/search affordance — **done**
   - Keep text search, but add an explicit Event ID dropdown.
   - Ensure Event ID displays whenever present.
   - Reason: event IDs are key IR pivots.

6. Improve log-source hints and summaries — **done for landing-page hints and current card summaries**
   - Keep current event-card layout.
   - PowerShell 4104 cards show script-block excerpts when present in normalized descriptions.
   - Reason: avoids scary-but-useless warnings.

## P2 — contained network/process pivots

Useful, but a little more code than log navigation.

7. Network remote-address filtering/sorting — **done**
   - Added remote IP search/sort and external-only/public-remote toggle.
   - Reason: analysts need to isolate external connections quickly.

8. Network PID links back to Process page — **done**
   - PID values link to `/processes?pid=<pid>`; process names link to a process search.
   - Reason: direct analyst workflow from connection to owning process.

9. Process search/labels cleanup — **done**
   - Partial/case-insensitive matching already exists.
   - Placeholder text now matches new labels.
   - Reason: small trust/UX improvement.

## P3 — slightly larger but still local UI work

Do after P0-P2 unless specifically requested.

10. Host Overview network/ipconfig friendly page — **done**
    - Added `/cases/{id}/network-config` with readable global network settings and adapter cards from normalized `network_ipconfig`.
    - Host Overview links to the friendly network configuration page instead of sending analysts straight to raw JSON.
    - Visible UI uses **Host Overview**; legacy `/host-context` route still works for compatibility.
    - Reason: removes another raw JSON escape hatch.

11. Artifact detail true counts + pagination — **done**
    - Raw artifact pages show current range and total normalized records with previous/next paging.
    - Reason: useful fallback, but less urgent if analyst pages are improving.

12. Scheduled task date sorting/filtering — **partially done**
    - Added time-text filter and sort options for last run, next run, and start time.
    - Created/modified timestamps are still pending because they are not consistently present in the current normalized scheduled-task records.
    - Reason: valuable, but parsing dates across task output may be fiddly.

## Defer until rate limits are comfortable

These are important but likely to burn more tokens or require broader design.

- Finding evidence deep links — **partially done** for current rule-engine findings: PowerShell 4104 links to filtered log view; scheduled-task findings link to exact record anchors; persistence findings link to the friendly Persistence page at exact record anchors. Future work should store structured evidence refs in dedicated columns/schema rather than encoded text.
- Persistence friendly page — **done**: case page links to `/cases/{id}/persistence`, with HKCU Run, HKCU RunOnce, and Startup Folder entries shown in analyst-friendly cards with filters, user-writable hints, and raw artifact fallbacks.
- Main case artifact source links — **done**: normalized artifact table now shows collected source artifact paths like `logs/system-events.txt` and links to `/cases/{id}/source/{artifact_key}` for a collected-source preview, instead of showing local normalized JSON/source storage paths.
- Notes + disposition editing UI
- Report export
- Analyst-tunable rule controls
- Multi-device same-case correlation
- Cross-case IOC search
- Dedicated schemas replacing generic normalized tables
- SEKER collector upgrades for WMI/CIM process command path/PPID
- File triage, security posture, installed-program inventory, Wi-Fi/Bluetooth/device inventory

## Suggested next implementation slice

The earlier low-token UI cleanup slice is now largely complete. The next high-value slice is workflow-oriented:

1. Case notes + disposition editing UI
2. Report export from DB-backed case state
3. Findings suppression / analyst-tunable rule controls
4. Dashboard polish for cases/findings needing review

If staying very small, start with case notes + disposition because it unlocks useful reports and makes Thoth a review workflow instead of only a viewer.
