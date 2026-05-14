# V1 Artifact List

## Scope assumption

This V1 list is for a **Windows-first**, **USB-run**, **no-install**, **no-admin** triage collector.

Goal:
- collect a useful first-pass triage package
- avoid privileged acquisition claims
- keep operator interaction minimal

## Collection tiers

### Tier A — Must have in V1
These are high-value and realistic without admin on most Windows systems.

#### 1. Case + operator metadata
Collect:
- case ID
- operator ID or initials
- asset label / hostname as entered by operator
- optional short notes
- collector version
- start/end timestamps

Why:
- chain-of-custody-lite and repeatability

#### 2. Host identity
Collect:
- hostname
- current username
- domain/workgroup
- OS name, version, build
- architecture
- local time and timezone
- last boot time / uptime

Why:
- basic scoping and timeline context

#### 3. Process inventory
Collect:
- running process list
- PID / PPID where available
- executable path where available
- command line where available
- process owner where available

Why:
- high signal for suspicious execution and quick analyst pivots

Caveat:
- some command-line or owner detail may be incomplete without elevation
- current early collector output may rely on `tasklist /fo csv /v`; upgrade SEKER to attempt WMI/CIM process detail collection for executable path, command line, and parent process ID, then fall back cleanly when unavailable

#### 4. Network state
Collect:
- IP configuration
- DNS servers
- routes
- ARP cache
- active listening ports
- active network connections
- associated process IDs where available

Why:
- fast signal for beaconing, exposed services, and odd routing/DNS

#### 5. Logged-on user context
Collect:
- current interactive users
- recent sessions where available from user-readable commands
- environment variables
- user profile path

Why:
- helps tie artifacts to likely user activity

#### 6. Services and scheduled tasks (readable subset)
Collect:
- services list
- service status
- service binary path where available
- scheduled task inventory where readable
- task command/action where available

Why:
- common persistence and execution footholds

#### 7. Startup / persistence artifacts reachable without admin
Collect:
- HKCU Run / RunOnce
- Startup folder contents for current user
- common Startup folder contents if readable
- user-accessible WMI persistence indicators if discoverable
- common autorun file locations in user space

Why:
- strong value for low-cost triage

#### 8. User-space file triage
Collect:
- recently modified executables/scripts in user profile scope
- files in Downloads/Desktop/Documents matching suspicious extensions
- temp-directory executable/script hits
- archive files of interest in user-accessible locations
- file metadata and hashes for flagged items

Why:
- good balance between signal and low privilege

Scope guardrail:
- default to metadata + targeted hashing first
- avoid copying whole home directories in V1

#### 9. Security tooling posture
Collect:
- registered AV/security product names where readable
- quick Windows Defender posture where readable without admin:
  - prefer `Get-MpComputerStatus`
  - capture `AMServiceEnabled`, `AntivirusEnabled`, `RealTimeProtectionEnabled`, `BehaviorMonitorEnabled`, `AntispywareEnabled`, `IoavProtectionEnabled`, signature versions/dates, and last quick/full scan fields when available
  - capture `WinDefend` service status as fallback/context when Defender cmdlets are unavailable
- Windows Firewall profile posture:
  - collect `netsh advfirewall show allprofiles`
  - capture Domain/Private/Public state ON/OFF and default inbound/outbound policy where readable
- EDR/service presence by process/service name heuristics

Why:
- gives analysts a fast Defender = on/off and Firewall = on/off readout for initial risk interpretation
- helps interpret both exposure and blind spots

Caveat:
- Defender operational logs are useful context but should not be treated as the authoritative on/off posture signal by themselves
- third-party AV/EDR may disable or replace Defender components, so display posture with source/confidence rather than a simplistic pass/fail

#### 9a. Installed-program inventory
Collect:
- installed-program entries from readable uninstall registry keys:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- display name, publisher, display version, install date, install location/source, and uninstall string where readable
- source hive/path for each entry so analysts can distinguish machine-wide vs per-user installs

Why:
- lets analysts quickly compare endpoint software against an approved-program baseline
- helps spot unexpected remote-access tools, admin utilities, dual-use tooling, security tools, or recently added software

Caveat:
- portable apps may not appear because they do not register uninstall entries
- Microsoft Store/UWP apps may be incomplete from these registry keys
- install dates are often missing or unreliable
- avoid `Win32_Product`; it can trigger MSI repair/reconfiguration and is not appropriate for quiet triage

#### 10. Readable event and script logs
Collect:
- recent Application log slice if readable
- recent System log slice if readable
- recent PowerShell operational log slice if readable
- Windows Defender operational entries if readable

Why:
- often enough to catch crash/error/execution clues even without Security log access

Caveat:
- Security log should be assumed unavailable in this mode

#### 11. USB + device context (readable subset)
Collect:
- current disk/volume inventory
- mounted removable media info, including drive letter/mount point, volume label, filesystem, size/free space, and removable classification where available
- currently connected USB/removable storage devices where readable
- previously seen USB storage devices from readable source-backed evidence first:
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USB`
  - `HKLM\SYSTEM\MountedDevices`
  - readable USB/storage PnP output
- PnP device summary where readable, including friendly name, device ID, manufacturer, class, status, and bus/interface clues
- lightly parsed device/vendor/product/serial-ish ID, friendly name, source registry path, and mounted volume/drive mapping when available
- recent USB/device indicators only if accessible without fragile parsing

Why:
- useful if staging media or rogue device questions come up
- gives Host Overview a quick answer to "what USB/removable devices are connected or visible right now?"
- gives Host Overview a source-backed "previously seen USB storage devices" section without pretending to be full USB forensics

Caveat:
- avoid brittle forensic parsing that requires admin or fragile registry assumptions in baseline mode; show source/confidence when recent-device history is partial
- label confidence clearly, for example `current`, `previously seen`, or `volume mapping observed`
- defer richer first/last-seen timeline reconstruction to a later enrichment pass using `setupapi.dev.log`, device properties, ContainerID/ClassGUID, and user MountPoints2 where readable

#### 12. Collector integrity artifacts
Collect:
- manifest of every collected file
- SHA-256 hashes
- collector execution log
- stderr/stdout capture for acquisition commands
- acquisition errors/warnings list

Why:
- makes hub ingest and troubleshooting much cleaner

---

### Tier B — Nice to have in V1 if low-friction
Useful, but only if they stay reliable and no-admin.

#### 13. Browser triage metadata
Collect:
- installed browser list
- browser process list
- profile paths
- extension inventory by manifest files where readable
- download-history database copies only when safe and readable

Why:
- useful for phishing and payload-delivery investigations

Caveat:
- live browser SQLite files can be locked or messy

#### 14. Prefetch / shimcache-adjacent indicators
Collect:
- prefetch filenames and timestamps if readable
- lightweight execution-history indicators that do not need invasive parsing

Why:
- can add strong execution context

Caveat:
- keep this simple in V1; deep parsers can wait

#### 15. Basic registry exports from readable keys
Collect:
- selected non-sensitive HKCU keys relevant to persistence or execution
- narrow HKLM keys only if consistently readable without admin

Why:
- good signal, but easy to overcomplicate

---

### Tier C — Explicitly out of scope for no-admin V1
Do not promise these in the baseline collector.

Out of scope:
- memory capture
- disk imaging
- Security.evtx full acquisition
- SAM / SYSTEM / SECURITY hive capture
- LSASS or credential material collection
- kernel or driver memory/state inspection
- raw browser credential stores
- protected EDR databases
- stealthy or anti-forensic behavior

## Recommended V1 bundle layout

```text
case-<id>/
  manifest.json
  hashes.sha256
  collector-log.txt
  errors.json
  operator-notes.txt
  host/
    identity.json
    uptime.txt
    environment.txt
  processes/
    process-list.csv
    process-details.json
  network/
    ipconfig.txt
    routes.txt
    arp.txt
    net-connections.csv
  persistence/
    hkcu-run.json
    startup-files.csv
    services.csv
    scheduled-tasks.csv
  files/
    suspicious-files.csv
    hashes.csv
  security/
    av-status.json
    firewall-status.txt
    defender-readable-events.txt
  logs/
    application-events.txt
    system-events.txt
    powershell-operational.txt
  devices/
    disks.txt
    pnp-summary.txt
```

## Prioritization recommendation

The list below is a **build priority**, not the final acquisition order. Build can proceed by feature area, but the collector should execute commands in the contamination-aware run order that follows.

If we cut to the bone for the first real collector pass, build in this order:

1. host identity
2. process inventory
3. network state
4. services + scheduled tasks
5. HKCU/user-space persistence
6. suspicious file triage + hashing
7. readable logs
8. security tooling posture
9. manifest + hashes + error handling

## Locked SEKER acquisition run order

For the next SEKER iteration, execute collection phases in this order to maximize volatile data capture and minimize collector-created log contamination:

1. **Minimal preflight only**
   - create output/bundle folders
   - record collector start time, version, media label, operator metadata, and target label
   - avoid PowerShell, WMI/CIM, broad file walks, or noisy inventory commands in this phase
2. **Most volatile live state**
   - process quick snapshot first
   - active/listening network connections with PIDs
   - ARP cache
   - routes
   - IP configuration and DNS server context
   - DNS cache
3. **Contamination-sensitive logs before PowerShell/WMI/CIM collectors**
   - PowerShell Operational log before any SEKER PowerShell usage
   - System and Application log slices
   - Defender Operational log
   - future WMI-Activity Operational log if SEKER starts using WMI/CIM for richer collection
4. **Host and user/session context**
   - hostname, OS/build, architecture, timezone/local time, boot time/uptime
   - current user, profile path, environment, logged-on/session context where readable
5. **Execution and persistence inventory**
   - services
   - scheduled tasks
   - HKCU Run/RunOnce
   - Startup folders and user-space autoruns
   - prefer native Go or low-noise command collection over PowerShell where practical
6. **Security posture**
   - firewall profile posture
   - Defender posture
   - security tool/EDR hints from process, service, and software inventory
   - if `Get-MpComputerStatus` is used, run it only after PowerShell logs have already been collected
7. **Device and software inventory**
   - disk/volume/removable-device state
   - USB/PnP readable inventory and source-backed previous-USB indicators
   - installed-program registry inventory from uninstall keys; never use `Win32_Product`
   - Wi-Fi/Bluetooth context where safely readable
8. **User-space file triage and hashing**
   - targeted metadata-first triage
   - targeted hashes for suspicious candidates
   - avoid broad copying or whole-profile traversal in baseline mode
9. **Final integrity outputs**
   - collector log
   - structured errors/warnings
   - manifest
   - hashes
   - collection end timestamp/status

Minimum immediate fix to current code: move readable log collection ahead of persistence because current persistence collection runs a PowerShell Startup-folder command before collecting the PowerShell Operational log.

## Honest product language for V1

Use language like:
- "baseline triage collector"
- "non-invasive first-pass collection"
- "user-context acquisition"
- "no-install collector"

Avoid language like:
- "full forensic collection"
- "complete host acquisition"
- "IR-ready for all evidence needs"

Because that would be bullshit, and I’d rather we not ship bullshit.
