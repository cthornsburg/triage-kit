#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./cmd/review-cli doctor
