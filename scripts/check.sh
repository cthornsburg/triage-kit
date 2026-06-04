#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Collector tests"
(
  cd "$repo_root/collector"
  go test ./...
)

echo "==> Hub tests"
(
  cd "$repo_root/hub"
  go test ./...
)

echo "==> Sample manifest validation"
(
  cd "$repo_root"
  python3 scripts/validate_sample_manifests.py
)

echo "OK: all checks passed"
