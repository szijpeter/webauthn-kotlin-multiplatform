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
        exclusiveContent {
            forRepository {
                mavenLocal()
            }
            filter {
                includeGroup("io.github.szijpeter")
            }
        }
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
    exclusiveContent {
        forRepository {
            mavenLocal()
        }
        filter {
            includeGroup("io.github.szijpeter")
        }
    }
    mavenCentral()
    google()
}

dependencies {
    implementation(platform("io.github.szijpeter:webauthn-bom:$VERSION_NAME"))
    implementation("io.github.szijpeter:webauthn-core")
    implementation("io.github.szijpeter:webauthn-crypto-api")
    implementation("io.github.szijpeter:webauthn-client-json-core")
    implementation("io.github.szijpeter:webauthn-network-ktor-client")
}

kotlin {
    compilerOptions {
        allWarningsAsErrors.set(true)
        freeCompilerArgs.add("-Xreturn-value-checker=check")
    }
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

cat > "$tmp_dir/src/main/kotlin/smoke/MustUseProbe.kt" <<'EOF'
package smoke

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.core.WebAuthnCoreValidator
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.model.CosePublicKey

fun ignoreSecurityResults(
    input: RegistrationValidationInput,
    signatureVerifier: SignatureVerifier,
    algorithm: CoseAlgorithm,
    publicKey: CosePublicKey,
    data: ByteArray,
    signature: ByteArray,
) {
    WebAuthnCoreValidator.validateRegistration(input)
    signatureVerifier.verify(algorithm, publicKey, data, signature)
}
EOF

set +e
probe_output="$(
    "$ROOT_DIR/gradlew" \
        --project-dir "$tmp_dir" \
        --no-daemon \
        --rerun-tasks \
        compileKotlin \
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
