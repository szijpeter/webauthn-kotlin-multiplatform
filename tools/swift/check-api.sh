#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--update] <derived-data-path>" >&2
}

mode="check"
if [[ "${1:-}" == "--update" ]]; then
  mode="update"
  shift
fi
if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
derived_data="$1"
baseline="$repo_root/swift/api/WebAuthn.swiftinterface"
interface="$(find "$derived_data/Build/Products" -type f -path '*/WebAuthn.swiftmodule/arm64-apple-ios-simulator.swiftinterface' -print -quit)"
if [[ -z "$interface" ]]; then
  echo "No arm64 WebAuthn.swiftinterface found under $derived_data" >&2
  exit 1
fi

temporary="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-swift-api.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
normalized="$temporary/WebAuthn.swiftinterface"
sed '/^\/\/ swift-interface-format-version:/d; /^\/\/ swift-compiler-version:/d; /^\/\/ swift-module-flags:/d; /^\/\/ swift-module-flags-ignorable:/d' \
  "$interface" > "$normalized"

if grep -E -n '/Users/|WebAuthnBridge\.' "$normalized"; then
  echo "The public Swift API contains a build-machine path or generated bridge type." >&2
  exit 1
fi

if [[ "$mode" == "update" ]]; then
  cp "$normalized" "$baseline"
  echo "Updated ${baseline#"$repo_root/"}."
  exit 0
fi

if [[ ! -f "$baseline" ]]; then
  echo "Missing Swift API baseline: ${baseline#"$repo_root/"}" >&2
  echo "Run $0 --update <derived-data-path> after reviewing the public API." >&2
  exit 1
fi
if ! diff -u "$baseline" "$normalized"; then
  echo "Swift public API drift detected. Review compatibility before updating the baseline." >&2
  exit 1
fi
echo "Swift public API baseline matches."
