# SEKER

Endpoint-side USB collector skeleton for the incident-response kit.

## Direction

This collector is **Windows-first**.

The intended production baseline is:
- run from removable media on Windows endpoints
- no install
- no admin for baseline triage
- deterministic case bundle output for later hub ingest

macOS and Linux collection paths currently exist as **best-effort developer harnesses** so local plumbing can be exercised off Windows. They are not the primary target and should not be treated as equivalent validation.

## Current scope

This slice now includes:
- Go module + `seker` entrypoint
- case/batch folder creation
- manifest data models aligned to the draft shared schemas
- JSON manifest writing
- SHA-256 helper
- real host identity collection into `host/identity.json`
- real process inventory collection, with Windows target output at `processes/process-list.csv`
- real network collection into `network/` for Windows-first interface/IP config, routes, active connections, and DNS info
- real persistence collection into `persistence/` for Windows-first current-user autoruns, startup-folder inventory, and scheduled-task inventory
- real readable log collection into `logs/` for Windows-first event-log slices
- collector metadata outputs: `collector-log.txt`, `errors.json`, `hashes.sha256`

File triage is deferred to SEKER v2.0. Security posture, software inventory, and device/removable-media inventory are implemented in the current Windows-first baseline.

## Layout

- `cmd/seker` — CLI entrypoint
- `internal/app` — top-level collection flow
- `internal/casebundle` — deterministic batch/case folder creation
- `internal/model` — bundle and batch manifest structs
- `internal/collect` — Windows-first collectors with fallback dev-harness paths for macOS/Linux
- `internal/writejson` — JSON writer helper
- `internal/checksum` — SHA-256 file helper

## Build

Canonical binary names:
- Windows: `seker.exe`
- macOS/Linux: `seker`

From `collector/`:

```bash
go build -o bin/seker ./cmd/seker
GOOS=windows GOARCH=amd64 go build -o bin/seker.exe ./cmd/seker
```

## Run locally

Local macOS/Linux runs are useful for plumbing checks only:

```bash
go run ./cmd/seker \
  --output-dir ../samples/local-dev-output \
  --hostname WS-LOCAL \
  --operator-id dev-operator \
  --media-label USB-LOCAL
```

## Expected Windows-first output shape

```text
samples/.../case-<host>-<timestamp>/
  manifest.json
  hashes.sha256
  collector-log.txt
  errors.json
  host/
    identity.json
  processes/
    process-list.csv
  network/
    ipconfig.txt
    routes.txt
    net-connections.txt
    dns-info.txt
  persistence/
    hkcu-run.txt
    hkcu-runonce.txt
    startup-folder.txt
    scheduled-tasks.csv
  security/
    firewall-status.txt
    defender-status.json
    security-products.json
  logs/
    application-events.txt
    system-events.txt
    powershell-operational.txt
    defender-operational.txt
```

## Current real coverage

### Windows-first collectors already implemented in code

- Host identity
  - `host/identity.json`
  - source: hostname + environment/user context
- Process inventory
  - `processes/process-list.csv`
  - source: `tasklist /fo csv /v`
- Network
  - `network/ipconfig.txt` from `ipconfig /all`
  - `network/routes.txt` from `route print`
  - `network/net-connections.txt` from `netstat -ano` (stored honestly as raw text in baseline mode)
  - `network/dns-info.txt` from `ipconfig /displaydns`
- Persistence
  - `persistence/hkcu-run.txt` from `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `persistence/hkcu-runonce.txt` from `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `persistence/startup-folder.txt` from the current-user Startup folder directory listing
  - `persistence/scheduled-tasks.csv` from `schtasks /query /fo csv /v`
- Logs
  - `logs/application-events.txt` from `wevtutil qe Application /c:1000 /rd:true /f:text`
  - `logs/system-events.txt` from `wevtutil qe System /c:1000 /rd:true /f:text`
  - `logs/powershell-operational.txt` from `wevtutil qe Microsoft-Windows-PowerShell/Operational /c:1000 /rd:true /f:text`
  - `logs/defender-operational.txt` from `wevtutil qe Microsoft-Windows-Windows Defender/Operational /c:1000 /rd:true /f:text`
  - These are recent collected-event slices, not full historical Windows Event Log exports. Older bundles may contain only the most recent 100 events per log.
- Security posture (after log capture)
  - `security/firewall-status.txt` from `netsh advfirewall show allprofiles`
  - `security/defender-status.json` from `Get-MpComputerStatus` plus `sc query WinDefend` fallback context
  - `security/security-products.json` from keyword hints in readable process/service names
- Collector metadata
  - `collector-log.txt`
  - `errors.json`
  - `hashes.sha256`
  - manifest artifact entries for all collected files

### macOS/Linux status

macOS and Linux remain fallback/dev-harness paths only.
They currently help verify:
- case bundle creation
- manifest writing
- artifact hashing
- command execution and partial/error handling

They do **not** count as production validation for the Windows collector.

## Deferred to SEKER v2.0

- suspicious file triage

## Locked next-iteration run order

The next SEKER iteration should change runtime acquisition order to maximize volatile capture and minimize collector-created log contamination:

1. minimal preflight only
2. most volatile live state: processes, active/listening connections, ARP, routes, IP/DNS context, DNS cache
3. contamination-sensitive logs before PowerShell/WMI/CIM collectors: PowerShell Operational, System/Application, Defender Operational, and future WMI-Activity if used
4. host identity plus user/session context
5. services, scheduled tasks, HKCU Run/RunOnce, Startup folders, and user-space persistence
6. security posture
7. device and installed-program inventory
8. final collector log, errors/warnings, manifest, hashes, and end status

File triage and targeted file hashing are deferred to SEKER v2.0.

Immediate correction from the current implementation: move readable log collection ahead of persistence because the current Startup-folder collector invokes PowerShell before the PowerShell Operational log is collected.

## Windows-first roadmap note

A real Windows verification pass still needs to confirm:
- commands run correctly from removable media in the intended operator workflow
- output filenames and formats match expectations on actual Windows hosts
- OS/version/build metadata in `host/identity.json` and the manifest match real Windows host details rather than collector runtime details
- `tasklist`, `netstat`, `ipconfig /displaydns`, `reg query`, `schtasks`, and `wevtutil` behave acceptably without elevation in baseline mode
- empty or access-limited cases are marked `partial` cleanly instead of looking successful
- scheduled-task and event-log output sizes/runtimes are acceptable on real endpoints
- manifest notes/status values are accurate for real Windows edge cases
- PowerShell and Defender operational logs degrade cleanly when the channels are unavailable

## Notes

- The manifest structs track the current draft schemas, but the shared JSON Schema references an `artifact-record.schema.json` file that is not present yet.
- `target_host.os_family` is normalized to `macos` for Go `darwin`; other supported values pass through directly.
- Windows is the explicit priority for collector design and artifact expectations.
- macOS/Linux notes in artifacts should be read as fallback harness caveats, not product promises.
