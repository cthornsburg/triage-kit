#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-1.0}"
label="${2:-rc}"
desktop_exe="${DESKTOP_SEKER_EXE:-$HOME/Desktop/seker.exe}"
release_dir="$repo_root/releases/seker/$version"
archive_dir="$release_dir/archive"
collector_dir="$repo_root/collector"

mkdir -p "$release_dir" "$archive_dir"

if [[ -f "$desktop_exe" ]]; then
  old_sha="$(shasum -a 256 "$desktop_exe" | awk '{print $1}')"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup="$archive_dir/seker-before-$label-$stamp-$old_sha.exe"
  cp -p "$desktop_exe" "$backup"
  echo "Archived existing Desktop exe: $backup"
fi

(
  cd "$collector_dir"
  GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$desktop_exe" ./cmd/seker
)

sha="$(shasum -a 256 "$desktop_exe" | awk '{print $1}')"
size="$(stat -f%z "$desktop_exe")"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
commit="$(cd "$repo_root" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

cp -p "$desktop_exe" "$release_dir/seker.exe"
cp -p "$desktop_exe" "$release_dir/seker-$version-$label.exe"
cat > "$release_dir/SHA256SUMS.txt" <<SUMS
$sha  seker.exe
$sha  seker-$version-$label.exe
SUMS
cat > "$release_dir/BUILD_NOTES.md" <<NOTES
# SEKER $version $label Build Notes

- Build label: \`$version-$label\`
- Built at: \`$stamp\`
- Source commit: \`$commit\`
- Binary: \`seker.exe\`
- Size: \`$size\` bytes
- SHA-256: \`$sha\`

Desktop output: \`$desktop_exe\`
Release copy: \`$release_dir/seker.exe\`
Rollback archive: \`$archive_dir\`
NOTES

echo "Built $desktop_exe"
echo "SHA-256 $sha"
echo "Release copy: $release_dir/seker.exe"
