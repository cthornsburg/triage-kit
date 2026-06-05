# SEKER Baseline Status and Roadmap

Status date: 2026-05-14

SEKER is the endpoint-side collector for the incident-response kit. The current public baseline is Windows-first, removable-media friendly, no-install, and designed for no-admin triage collection.

## Guiding constraints

- Windows-first
- USB-run / removable-media friendly
- no install
- no-admin baseline
- read-only system information collection
- deterministic bundle output for Thoth ingest
- maximize volatile capture before slower inventory work
- collect PowerShell/WMI/CIM-sensitive logs before running PowerShell/WMI/CIM collectors
- prefer native Go or low-noise Windows commands where practical
- avoid commands known to mutate endpoint state, especially `Win32_Product`
- do not collect Wi-Fi keys/passwords
- do not claim forensic completeness

## Public CLI / identity model

Implemented:

- `seker --help` no longer exposes `--case-id` or `--dry-run`.
- SEKER does not own analyst-facing case identity.
- SEKER emits `bundle_id` as the collection identity.
- SEKER emits/generates `batch_id` for media/run grouping when one is not supplied.
- Thoth ingest assigns or accepts the analyst-facing Case ID.
- Thoth stores SEKER `bundle_id` as Collection ID.
- Duplicate ingest protection remains keyed on `batch_id` + `bundle_id`.

Label convention:

- **Case ID** = Thoth analyst-facing ID
- **Collection ID** = SEKER `bundle_id`
- **Batch ID** = SEKER grouping ID

## Implemented SEKER v1 baseline

### Runtime order

Current operator-visible order:

1. Identifying Host
2. Collecting Process IDs
3. Collecting Network Data
4. Collecting Log Data
5. Identifying Processes
6. Persistence Checks
7. Security Status
8. Software Inventory
9. Verifying Removable Media

The order intentionally captures logs before later PowerShell/WMI/CIM-heavy collectors so collection self-noise is visible but not injected before the log slice.

### Host/session enrichment

Implemented in `host/identity.json`:

- hostname
- current user/profile context
- domain/workgroup context where readable
- environment/session context where readable
- OS/runtime metadata
- boot time
- uptime
- source/confidence fields
- missing-field warnings

Thoth Host Overview displays the collected boot/uptime and host context with source-aware language.

### Process collection

Implemented:

- fallback process inventory from `tasklist /fo csv /v`
- richer post-log process detail via `Get-CimInstance Win32_Process`
- PID
- PPID
- process name
- executable path where readable
- command line where readable
- owner/user where readable
- graceful fallback when richer detail is unavailable

### Network collection

Implemented:

- interface/IP configuration
- routes
- active/listening network connections
- DNS cache where readable
- Wi-Fi interface/profile metadata without key material
- Bluetooth PnP/connected-device context where readable
- Thoth virtual/container/VM/VPN adapter hints, including Hyper-V, WSL, Docker, VMware, VirtualBox, VPN/tunnel, Npcap/loopback, and Bluetooth PAN style context

### Logs

Implemented readable Windows log slices:

- Application
- System
- PowerShell Operational
- Defender Operational

Thoth keeps visible collection self-noise hints instead of silently suppressing them.

### Persistence

Implemented baseline user/system-readable persistence checks:

- HKCU Run
- HKCU RunOnce
- current-user Startup folder
- scheduled tasks inventory where readable

### Security posture

Implemented:

- Windows Firewall profile posture via `netsh advfirewall show allprofiles`
- Defender posture via `Get-MpComputerStatus` where available
- `WinDefend` service fallback/context
- security-tool hints from readable process/service names
- confidence/notes language so absence or replacement by third-party tools is not overclaimed

### Installed-program inventory

Implemented from no-admin uninstall registry sources:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`

Captured fields include:

- display name
- publisher
- display version
- install date, with reliability label
- install location/source
- uninstall string
- quiet uninstall string where present
- source hive/path/scope

Hard rule retained: do **not** use `Win32_Product`.

### Device and removable-media inventory

Implemented:

- logical disk / volume inventory
- current removable/USB media indicators
- drive letter/mount point
- volume label
- filesystem
- size/free space
- removable/bus/interface classification where readable
- PnP/storage summaries
- current USB device evidence
- source-backed previous USB evidence from:
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USB`
  - `HKLM\SYSTEM\MountedDevices`

Confidence labels separate current devices, previously seen evidence, and volume mapping observations.

## Current validation gates

Before release or public-preview promotion, use:

```bash
cd collector && go test ./...
cd hub && go test ./...
python3 scripts/validate_sample_manifests.py
```

Recommended smoke checks:

```bash
cd collector
go run ./cmd/seker --output-dir /tmp/seker-smoke --hostname smoke-host --operator-id smoke --media-label USB-SMOKE
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /tmp/seker.exe ./cmd/seker
```

Then ingest the generated `/tmp/seker-smoke` output with Thoth.

## Deferred to SEKER v2.0

### User-space file triage

Deferred because it is slower, noisier, easier to over-scope, and more likely to create acquisition-time side effects than the current Host Overview feeder collections.

Potential v2.0 scope:

- suspicious file triage
- targeted file hashing from Downloads/Desktop/Documents/Temp
- archive/script/executable candidate scoring
- browser download-history database handling

Guardrails for v2.0:

- do not recurse broadly by default
- cap file counts and runtime
- avoid opening/altering user files where metadata is enough
- label output as triage leads, not forensic completeness

### Richer USB timeline reconstruction

Deferred to a later enrichment pass.

Potential sources:

- `setupapi.dev.log`
- device properties
- ContainerID/ClassGUID
- user MountPoints2 where readable

Guardrail:

- do not overclaim first/last-seen timestamps in baseline mode.

## Later / optional roadmap

- Windows Server coverage
- optional elevated collector mode
- memory-capture-aware workflow in the elevated path
- SEKER USB clear/reprepare workflow after ingest, only after Thoth media-targeting guardrails are strong enough
