#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <output-directory>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(tr -d '[:space:]' < "$repo_root/sample/swift-passkey/.xcodegen-version")"
case "$version" in
  2.45.3)
    checksum="0c90f4d28ca57335f9fa78cf5bf6dabfe20a232036dabe36de2eef79cb7c0878"
    ;;
  *)
    echo "No reviewed XcodeGen checksum for version $version." >&2
    exit 1
    ;;
esac

output_dir="$1"
mkdir -p "$output_dir"
archive="$output_dir/xcodegen.zip"
curl --fail --location --silent --show-error \
  "https://github.com/yonaskolb/XcodeGen/releases/download/$version/xcodegen.zip" \
  --output "$archive"
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 --check
unzip -q -o "$archive" -d "$output_dir"
"$output_dir/xcodegen/bin/xcodegen" --version
