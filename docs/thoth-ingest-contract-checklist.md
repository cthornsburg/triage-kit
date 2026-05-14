# Thoth Ingest Contract Checklist

Minimum SEKER contract assumptions Thoth depends on:

- each case has a predictable case root
- each case includes `manifest.json`
- each case includes `hashes.sha256`
- artifact paths in the manifest match on-disk layout
- batch-to-case relationship is recoverable from collected metadata
- collector version is present
- collection start/end timestamps are present
- hostname is present even when operator-entered asset labels vary
- error/warning reporting is preserved in a structured form
- partial collection failures are represented without making the whole bundle unreadable

Before building deeper normalization, verify these against the latest sample bundles.
