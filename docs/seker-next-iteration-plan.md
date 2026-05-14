# SEKER Next-Iteration Plan

Scope for the next SEKER iteration after the initial process/network/persistence/log baseline.

This plan intentionally excludes user-space file triage. Treat file triage and targeted file hashing as a **v2.0 feature** because it is slower, noisier, easier to over-scope, and more likely to create acquisition-time side effects than the Host Overview feeder collections below.

## Guiding constraints

- Windows-first
- USB-run
- no install
- no-admin baseline
- deterministic bundle output for Thoth ingest
- maximize volatile capture before slower inventory work
- collect PowerShell/WMI/CIM-sensitive logs before running PowerShell/WMI/CIM collectors
- prefer native Go or low-noise Windows commands where practical
- avoid commands known to mutate endpoint state, especially `Win32_Product`

## Locked acquisition order

1. Minimal preflight only
2. Most volatile live state: process and network snapshots
3. Contamination-sensitive logs before PowerShell/WMI/CIM collectors
4. Host identity and user/session context
5. Execution and persistence inventory
6. Security posture
7. Device and installed-program inventory
8. Final integrity outputs

File triage is deliberately absent from this v1.x sequence.

## Workstream 1 — sequencing correction

Goal: align existing collectors with the locked acquisition order.

- Move readable log collection ahead of persistence.
- Collect PowerShell Operational before any collector invokes PowerShell.
- Keep System, Application, and Defender log slices near the same early log phase.
- Preserve visible collection self-noise hints in Thoth; do not suppress these records silently.

Acceptance checks:
- SEKER runtime order is visible in code and collector log.
- PowerShell Operational log collection occurs before Startup-folder or Defender posture PowerShell calls.
- Existing Thoth normalization still imports the changed bundle layout/order.

## Workstream 2 — host/session enrichment

Goal: fill missing Host Overview context without adding noisy file-system traversal.

Collect:
- boot time / uptime
- current user and profile path cleanup
- domain/workgroup cleanup
- environment/session context where readable

Preferred output:
- `host/identity.json` expanded, or
- separate `host/uptime.txt`, `host/session-context.json`, and `host/environment.txt` if cleaner for Thoth normalization

Acceptance checks:
- Thoth Host Overview can display boot time/uptime with source/confidence.
- Missing or access-limited fields are marked partial, not silently blank.

## Workstream 3 — richer process detail

Goal: improve process pivots beyond `tasklist /fo csv /v`.

Collect where readable:
- PID
- PPID
- process name
- executable path
- command line
- owner/user where available

Implementation preference:
- attempt WMI/CIM or equivalent Windows API/native collection for richer fields
- gracefully fall back to `tasklist /fo csv /v`
- if PowerShell/WMI/CIM is used, ensure log snapshots already happened

Acceptance checks:
- Thoth process page can show PPID/path/command-line fields when present.
- Fallback output remains ingestible on restrictive hosts.

## Workstream 4 — security posture

Goal: give analysts a quick, sourced Defender/Firewall/security-tool posture view.

Collect:
- Windows Firewall profile posture via `netsh advfirewall show allprofiles`
- Defender posture fields where readable:
  - `AMServiceEnabled`
  - `AntivirusEnabled`
  - `RealTimeProtectionEnabled`
  - `BehaviorMonitorEnabled`
  - `AntispywareEnabled`
  - `IoavProtectionEnabled`
  - signature versions/dates
  - last quick/full scan fields where readable
- `WinDefend` service status as fallback/context
- EDR/security-tool hints from process/service/software names

Notes:
- If `Get-MpComputerStatus` is used, run it only after PowerShell Operational logs are collected.
- Display third-party AV/EDR cases with source/confidence instead of simplistic pass/fail.

Preferred output:
- `security/firewall-status.txt` or structured JSON if parsed directly
- `security/defender-status.json`
- `security/security-products.json` or `security/security-tools.txt`

Acceptance checks:
- Thoth Host Overview can show Defender and Firewall posture with source and confidence.
- Defender unavailable/replaced-by-third-party states degrade cleanly.

## Workstream 5 — installed-program inventory

Goal: support approved-software comparison and quick spotting of unexpected remote-access/admin/security tools.

Collect readable uninstall registry entries from:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`

Fields where present:
- display name
- publisher
- display version
- install date
- install location/source
- uninstall string
- source hive/path

Hard rule:
- do **not** use `Win32_Product`; it can trigger MSI repair/reconfiguration and is not acceptable for quiet triage.

Preferred output:
- `software/installed-programs.json` or `software/installed-programs.csv`

Acceptance checks:
- Thoth Host Overview can distinguish machine-wide vs per-user entries.
- Missing/unreliable install dates are labeled as such.

## Workstream 6 — device and removable-media inventory

Goal: give Host Overview a source-backed view of current and previously seen removable/USB context without pretending to be full USB forensics.

Collect current state:
- disk/volume inventory
- mounted removable media
- drive letter/mount point
- volume label
- filesystem
- size/free space
- removable/bus/interface classification where readable

Collect PnP/USB context:
- friendly name
- device ID
- manufacturer
- class
- status
- bus/interface clues

Collect previous-USB source-backed evidence first:
- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`
- `HKLM\SYSTEM\MountedDevices`
- readable USB/storage PnP output

Parse lightly:
- vendor/product/serial-ish ID where obvious
- friendly name
- source registry path
- mounted volume/drive mapping when available

Confidence labels:
- `current`
- `previously seen`
- `volume mapping observed`

Deferred:
- richer first/last-seen USB timeline reconstruction using `setupapi.dev.log`, device properties, ContainerID/ClassGUID, and user MountPoints2

Preferred output:
- `devices/volumes.json`
- `devices/pnp-summary.json`
- `devices/usb-current.json`
- `devices/usb-previous.json`

Acceptance checks:
- Thoth Host Overview clearly separates current vs previously seen vs volume mapping evidence.
- No baseline claim of complete USB forensic history.

## Workstream 7 — Wi-Fi, Bluetooth, and virtual adapter context

Goal: improve network/device interpretation without requiring admin.

Wi-Fi collection where readable:
- current SSID/BSSID
- adapter state
- saved profile metadata when safely available

Bluetooth collection where readable:
- adapter state
- paired devices
- recent device indicators when safely available

Virtual/container/VM adapter hints:
- Hyper-V
- WSL
- Docker
- VMware
- VirtualBox
- VPN
- Npcap/loopback

Acceptance checks:
- Thoth network details distinguish likely primary routed adapters from virtual/local-only adapters.
- Wi-Fi/Bluetooth output degrades cleanly when hardware/services are absent.

## Workstream 8 — manifest and metadata cleanup

Goal: keep SEKER collection identity stable without leaking analyst workflow assumptions into the collector.

- Remove reused/fallback `CASE-LOCAL-001` behavior.
- Keep stable bundle identity metadata for dedupe.
- Preserve hostname + collection time as useful context, not primary analyst case identity.
- Clean up username/domain fallback behavior.
- Ensure partial failures are represented clearly in manifest/errors.

Acceptance checks:
- Thoth remains owner of analyst-facing case IDs.
- Reusable media does not create ambiguous duplicate case identities.
- Manifest warnings/errors are actionable and source-specific.

## Deferred to SEKER v2.0

- user-space suspicious file triage
- targeted file hashing from Downloads/Desktop/Documents/Temp
- archive/script/executable candidate scoring
- browser download-history database handling
- broader execution-history parsing beyond low-friction metadata

Reason: these are valuable, but slower and noisier. They should ship after v1.x host, posture, device, and software context is stable.
