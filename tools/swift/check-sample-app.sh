#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Swift sample app inspection requires macOS." >&2
  exit 1
fi

app_path="${1:-}"
if [[ -z "$app_path" || ! -d "$app_path" ]]; then
  echo "Usage: $0 <WebAuthnSwiftDemo.app>" >&2
  exit 1
fi

info_plist="$app_path/Info.plist"
if [[ ! -f "$info_plist" ]]; then
  echo "Swift sample app is missing Info.plist: $info_plist" >&2
  exit 1
fi

assert_plist_value() {
  local key="$1"
  local expected="$2"
  local actual
  actual="$(/usr/libexec/PlistBuddy -c "Print :$key" "$info_plist" 2>/dev/null || true)"
  if [[ "$actual" != "$expected" ]]; then
    echo "Swift sample Info.plist key $key expected '$expected', found '$actual'." >&2
    exit 1
  fi
}

assert_plist_value WEBAUTHN_DEMO_ENDPOINT "http://127.0.0.1:8080"
assert_plist_value WEBAUTHN_DEMO_RP_ID "localhost"
assert_plist_value WEBAUTHN_DEMO_ORIGIN "https://localhost"
assert_plist_value WEBAUTHN_DEMO_USER_ID "42"
assert_plist_value WEBAUTHN_DEMO_USER_NAME "Zaphod Beeblebrox"

echo "Swift sample app contains the expected runtime configuration."
