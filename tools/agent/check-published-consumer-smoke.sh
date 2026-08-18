#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

KTOR_VERSION="$(sed -n 's/^ktor = \"\(.*\)\"/\1/p' gradle/libs.versions.toml | head -n 1)"

VERSION_NAME="$(sed -n 's/^VERSION_NAME=//p' gradle.properties | head -n 1)"
KOTLIN_VERSION="$(sed -n 's/^kotlin = "\(.*\)"/\1/p' gradle/libs.versions.toml | head -n 1)"
COROUTINES_VERSION="$(sed -n 's/^coroutines = "\(.*\)"/\1/p' gradle/libs.versions.toml | head -n 1)"
AGP_VERSION="$(sed -n 's/^agp = "\(.*\)"/\1/p' gradle/libs.versions.toml | head -n 1)"

if [[ -z "$VERSION_NAME" ]]; then
  echo "Unable to resolve VERSION_NAME from gradle.properties" >&2
  exit 1
fi

if [[ -z "$KOTLIN_VERSION" ]]; then
  echo "Unable to resolve Kotlin version from gradle/libs.versions.toml" >&2
  exit 1
fi

if [[ -z "$COROUTINES_VERSION" ]]; then
  echo "Unable to resolve coroutines version from gradle/libs.versions.toml" >&2
  exit 1
fi

if [[ -z "$AGP_VERSION" ]]; then
  echo "Unable to resolve Android Gradle Plugin version from gradle/libs.versions.toml" >&2
  exit 1
fi

if [[ -z "$KTOR_VERSION" ]]; then
  echo "Unable to resolve Ktor version from gradle/libs.versions.toml" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cp -R "$ROOT_DIR/documentation/consumer-smoke/." "$tmp_dir/"

for template in \
  "$tmp_dir/build.gradle.kts.template" \
  "$tmp_dir/client/build.gradle.kts.template" \
  "$tmp_dir/server/build.gradle.kts.template" \
  "$tmp_dir/json-kotlinx/build.gradle.kts.template"; do
  output="${template%.template}"
  sed \
    -e "s/<version>/$VERSION_NAME/g" \
    -e "s/<kotlin-version>/$KOTLIN_VERSION/g" \
    -e "s/<coroutines-version>/$COROUTINES_VERSION/g" \
    -e "s/<agp-version>/$AGP_VERSION/g" \
    -e "s/<ktor-version>/$KTOR_VERSION/g" \
    "$template" > "$output"
done

"$ROOT_DIR/gradlew" \
  --project-dir "$tmp_dir" \
  --no-daemon \
  :client:compileKotlinJvm \
  :client:compileTestKotlinJvm \
  :client:compileAndroidMain \
  :client:compileKotlinIosSimulatorArm64 \
  :server:compileKotlin \
  :json-kotlinx:compileKotlin \
  --stacktrace

cp \
  "$tmp_dir/probes/MustUseProbe.kt" \
  "$tmp_dir/server/src/main/kotlin/smoke/server/MustUseProbe.kt"

set +e
probe_output="$(
    "$ROOT_DIR/gradlew" \
        --project-dir "$tmp_dir" \
        --no-daemon \
        --rerun-tasks \
        :server:compileKotlin \
        --stacktrace 2>&1
)"
probe_exit_code="$?"
set -e

if [[ "$probe_exit_code" -eq 0 ]]; then
    echo "Must-use consumer probe unexpectedly compiled ignored security results" >&2
    exit 1
fi

for function_name in validateRegistration verify; do
    if ! grep -Fq "Unused return value of '$function_name'." <<< "$probe_output"; then
        echo "Must-use consumer probe did not report ignored '$function_name' result" >&2
        echo "$probe_output" >&2
        exit 1
    fi
done

echo "Published consumer smoke check: PASS"
