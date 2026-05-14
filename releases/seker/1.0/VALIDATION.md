# SEKER 1.0 Validation

Status: pending Windows live validation by Chip.

## Build validation completed

- [x] Windows amd64 binary generated as `seker.exe`
- [x] Dry-run manifest reports collector version `1.0`
- [x] SHA-256 recorded in `SHA256SUMS.txt`

## Windows validation checklist

- [ ] Copy `seker.exe` to USB/removable media
- [ ] Run on Windows without install/admin
- [ ] Confirm output folder is created under expected collection path
- [ ] Confirm bundle includes:
  - [ ] `manifest.json`
  - [ ] checksums/hashes
  - [ ] collector log
  - [ ] warnings/errors if any
  - [ ] host artifacts
  - [ ] process/network artifacts
  - [ ] logs before PowerShell/WMI/CIM collectors
  - [ ] persistence artifacts
  - [ ] security artifacts
  - [ ] software artifacts
  - [ ] device/removable-media artifacts
  - [ ] Wi-Fi/Bluetooth/network-context artifacts
- [ ] Import bundle into Thoth
- [ ] Run normalization/findings
- [ ] Confirm Host Overview displays new SEKER v1.0 context
- [ ] Record Windows host/test notes below

## Test notes

_TBD_
