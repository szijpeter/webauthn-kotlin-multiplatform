#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"
serial="${WEBAUTHN_ANDROID_TEST_SERIAL:-}"
if [[ -z "$serial" ]]; then
  serial="$(adb devices | python3 -c '
import sys
serials = [line.split()[0] for line in sys.stdin if line.startswith("emulator-") and line.split()[1] == "device"]
if len(serials) != 1:
    raise SystemExit("Select exactly one emulator with WEBAUTHN_ANDROID_TEST_SERIAL")
print(serials[0])
')"
fi
if [[ "$serial" != emulator-* ]]; then
  echo "This fixture driver requires an emulator; physical-provider tests are separate." >&2
  exit 2
fi
export ANDROID_SERIAL="$serial"
results="$repo_root/build/mobile-ui/android"
mkdir -p "$results"
run="$(mktemp -d "$results/run.XXXXXX")"
started_at="$(python3 -c 'import time; print(time.time())')"
collect_evidence() {
  status=$?
  trap - EXIT
  set +e
  output="$repo_root/sample/compose-passkey-android/build/outputs"
  if [[ -d "$output/connected_android_test_additional_output" ]]; then
    cp -R "$output/connected_android_test_additional_output" "$run/additional-output"
  fi
  python3 tools/mobile/record-test-run.py --out "$run/metadata.json" --platform android --destination "$serial" --status "$status" --started-at "$started_at"
  exit "$status"
}
trap collect_evidence EXIT
./gradlew :sample:compose-passkey-android:connectedDebugAndroidTest --stacktrace | tee "$run/test.log"
