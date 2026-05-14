#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/exports
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="data/exports/thoth-data-${stamp}.tar.gz"
tar -czf "$archive" data
printf 'Wrote backup: %s/%s\n' "$PWD" "$archive"
