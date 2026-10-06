#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"
simulator_id="${WEBAUTHN_IOS_TEST_SIMULATOR:-$(python3 tools/mobile/select-ios-simulator.py)}"
results="$repo_root/build/mobile-ui/compose-ios"
mkdir -p "$results"
run="$(mktemp -d "$results/run.XXXXXX")"
started_at="$(python3 -c 'import time; print(time.time())')"
record_result() {
  status=$?
  trap - EXIT
  set +e
  python3 tools/mobile/record-test-run.py --out "$run/metadata.json" --platform compose-ios --destination "$simulator_id" --status "$status" --started-at "$started_at"
  exit "$status"
}
trap record_result EXIT
xcodebuild -quiet \
  -project sample/compose-passkey-ios/ComposePasskeyIos.xcodeproj \
  -scheme ComposePasskeyIos -configuration Debug \
  -destination "platform=iOS Simulator,id=$simulator_id" \
  -derivedDataPath "$repo_root/.build/xcode-derived/compose-passkey-ios-ui" \
  -resultBundlePath "$run/Debug.xcresult" -collect-test-diagnostics never \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO test | tee "$run/test.log"
