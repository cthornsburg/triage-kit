# SEKER 1.0 RC1 Build Notes

- Build label: `1.0-rc1`
- Built/recorded at: `2026-05-13T21:48:11Z`
- Source commit at build time: `ff9d348`
- Binary: `seker.exe`
- Size: `3434496` bytes
- SHA-256: `ab024f6636e3e8c6d518d9d363eff2d2cd65cbe61a6ae7a4f7e32c9e7fb2a331`
- Build host: local maintainer workstation

## Build command

```bash
cd collector
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ./seker.exe ./cmd/seker
```

## Release contents

- `seker.exe` — current release candidate copy
- `SHA256SUMS.txt` — checksum file
- `VALIDATION.md` — Windows/Thoth validation checklist

Immutable or rollback-labeled executable copies are kept in local ignored archive folders, not published in the GitHub release directory.

## Rollback

Use the matching `seker.exe` from this folder. Verify with:

```bash
shasum -a 256 seker.exe
cat SHA256SUMS.txt
```

If a later build fails validation, use a known-good local archived executable or rebuild from the matching source commit before replacing `seker.exe`.
