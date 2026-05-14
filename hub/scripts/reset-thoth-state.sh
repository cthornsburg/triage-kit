#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf data
mkdir -p data/db data/imports data/cases data/quarantine data/exports data/tmp
printf 'reset_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > data/.reset-marker
printf 'Reset Thoth local state under %s/data\n' "$PWD"
