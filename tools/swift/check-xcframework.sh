#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
xcframework="${1:-$repo_root/client/webauthn-client-swift-bridge/build/XCFrameworks/release/WebAuthnBridge.xcframework}"
if [[ ! -d "$xcframework" ]]; then
  echo "Missing XCFramework: $xcframework" >&2
  exit 1
fi
deployment_scan="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-xcframework-minos.XXXXXX")"
trap 'rm -rf "$deployment_scan"' EXIT

python3 - "$xcframework/Info.plist" <<'PY'
import plistlib
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
with path.open("rb") as source:
    info = plistlib.load(source)
actual = {
    (
        item["LibraryIdentifier"],
        tuple(item["SupportedArchitectures"]),
        item["SupportedPlatform"],
        item.get("SupportedPlatformVariant"),
    )
    for item in info["AvailableLibraries"]
}
expected = {
    ("ios-arm64", ("arm64",), "ios", None),
    ("ios-arm64-simulator", ("arm64",), "ios", "simulator"),
}
if actual != expected:
    raise SystemExit(f"Unexpected XCFramework slices: {sorted(actual)}")

for framework_info in path.parent.glob("*/WebAuthnBridge.framework/Info.plist"):
    with framework_info.open("rb") as source:
        framework = plistlib.load(source)
    if framework.get("CFBundleIdentifier") != "dev.webauthn.swift.bridge":
        raise SystemExit(f"Unexpected framework bundle identifier: {framework_info}")
    version = framework.get("CFBundleShortVersionString", "")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise SystemExit(f"Invalid framework bundle version {version!r}: {framework_info}")
PY

for slice in ios-arm64 ios-arm64-simulator; do
  framework="$xcframework/$slice/WebAuthnBridge.framework"
  binary="$framework/WebAuthnBridge"
  manifest="$framework/PrivacyInfo.xcprivacy"
  license="$framework/LICENSE"
  notices="$framework/THIRD_PARTY_NOTICES.txt"
  [[ -f "$binary" ]] || { echo "Missing framework binary: $binary" >&2; exit 1; }
  [[ -s "$license" ]] || { echo "Missing framework license: $license" >&2; exit 1; }
  [[ -s "$notices" ]] || { echo "Missing framework third-party notices: $notices" >&2; exit 1; }
  cmp -s "$repo_root/LICENSE" "$license" || {
    echo "Framework license does not match the repository license: $license" >&2
    exit 1
  }
  cmp -s "$repo_root/swift/THIRD_PARTY_NOTICES.txt" "$notices" || {
    echo "Framework third-party notices are stale: $notices" >&2
    exit 1
  }
  [[ "$(lipo -archs "$binary")" == "arm64" ]] || {
    echo "Unexpected architecture in $binary: $(lipo -archs "$binary")" >&2
    exit 1
  }
  file "$binary" | grep 'current ar archive' >/dev/null || {
    echo "Expected a static framework archive: $binary" >&2
    exit 1
  }
  slice_scan="$deployment_scan/$slice"
  mkdir -p "$slice_scan"
  (cd "$slice_scan" && ar -x "$binary")
  while IFS= read -r -d '' object; do
    min_os="$(xcrun vtool -show-build "$object" 2>/dev/null | awk '/^[[:space:]]+minos / {print $2; exit}')"
    [[ -z "$min_os" ]] && continue
    python3 - "$min_os" "$object" <<'PY'
import sys

parts = [int(part) for part in sys.argv[1].split(".")]
version = tuple((parts + [0, 0, 0])[:3])
if version > (16, 0, 0):
    raise SystemExit(f"Object requires iOS {sys.argv[1]}, above package minimum: {sys.argv[2]}")
PY
  done < <(find "$slice_scan" -type f -name '*.o' -print0)
  plutil -lint "$manifest" >/dev/null
  if grep -a -q '/Users/' "$binary"; then
    echo "Build-machine path found in release binary: $binary" >&2
    exit 1
  fi
  if nm -u "$binary" 2>/dev/null | grep -E '(^|[[:space:]])(_mach_absolute_time|_stat|_fstat|_lstat|_statfs|_fstatfs|_getattrlist|_getattrlistbulk|_fgetattrlist|_CFPreferencesCopyAppValue|_OBJC_CLASS_\$_NSUserDefaults)$' >/dev/null; then
    echo "A required-reason API appeared; review and update PrivacyInfo.xcprivacy before release." >&2
    exit 1
  fi
done

python3 - "$xcframework" <<'PY'
import plistlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
for manifest in root.glob("*/WebAuthnBridge.framework/PrivacyInfo.xcprivacy"):
    with manifest.open("rb") as source:
        data = plistlib.load(source)
    expected = {
        "NSPrivacyAccessedAPITypes": [],
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
    }
    if data != expected:
        raise SystemExit(f"Unexpected privacy manifest contents: {manifest}")
PY

while IFS= read -r -d '' interface; do
  if grep -n '/Users/' "$interface"; then
    echo "Build-machine path found in a Swift interface: $interface" >&2
    exit 1
  fi
done < <(find "$xcframework" -type f -name '*.swiftinterface' -print0)

swift_smoke="$deployment_scan/BridgeLinkSmoke.swift"
cat > "$swift_smoke" <<'SWIFT'
import WebAuthnBridge

@main
struct BridgeLinkSmoke {
    static func main() {
        _ = SwiftPasskeyBridge()
    }
}
SWIFT
simulator_sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
xcrun --sdk iphonesimulator swiftc \
  -target arm64-apple-ios16.0-simulator \
  -sdk "$simulator_sdk" \
  -F "$xcframework/ios-arm64-simulator" \
  -framework WebAuthnBridge \
  -parse-as-library \
  -o "$deployment_scan/BridgeLinkSmoke" \
  "$swift_smoke"

echo "XCFramework structure, metadata, path hygiene, and Swift import/link checks passed."
