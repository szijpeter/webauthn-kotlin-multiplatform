#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

VERSION_NAME="$(sed -n 's/^VERSION_NAME=//p' gradle.properties | head -n 1)"
KOTLIN_VERSION="$(sed -n 's/^kotlin = "\(.*\)"/\1/p' gradle/libs.versions.toml | head -n 1)"

if [[ -z "$VERSION_NAME" ]]; then
  echo "Unable to resolve VERSION_NAME from gradle.properties" >&2
  exit 1
fi

if [[ -z "$KOTLIN_VERSION" ]]; then
  echo "Unable to resolve Kotlin version from gradle/libs.versions.toml" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cat > "$tmp_dir/settings.gradle.kts" <<EOF
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
        google()
    }
}

rootProject.name = "webauthn-published-consumer-smoke"
EOF

cat > "$tmp_dir/build.gradle.kts" <<EOF
plugins {
    kotlin("jvm") version "$KOTLIN_VERSION"
}

repositories {
    mavenLocal()
    mavenCentral()
    google()
}

dependencies {
    implementation(platform("io.github.szijpeter:webauthn-bom:$VERSION_NAME"))
    implementation("io.github.szijpeter:webauthn-client-json-core")
    implementation("io.github.szijpeter:webauthn-network-ktor-client")
}

kotlin {
    jvmToolchain(11)
}
EOF

mkdir -p "$tmp_dir/src/main/kotlin/smoke"
cat > "$tmp_dir/src/main/kotlin/smoke/Smoke.kt" <<'EOF'
package smoke

import dev.webauthn.client.KotlinxPasskeyJsonMapper
import dev.webauthn.network.KtorPasskeyServerClient
import io.ktor.client.HttpClient

fun smoke(mapper: KotlinxPasskeyJsonMapper, client: KtorPasskeyServerClient): String {
    return "${mapper::class.simpleName}:${client::class.simpleName}"
}

fun main() {
    val mapper = KotlinxPasskeyJsonMapper()
    val client = KtorPasskeyServerClient(
        httpClient = HttpClient(),
        endpointBase = "https://example.com",
    )
    check(smoke(mapper, client).isNotBlank())
}
EOF

"$ROOT_DIR/gradlew" --project-dir "$tmp_dir" --no-daemon compileKotlin --stacktrace
echo "Published consumer smoke check: PASS"
