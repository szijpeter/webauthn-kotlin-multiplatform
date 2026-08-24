# Mobile quickstart

This path creates a shared passkey flow for Android and iOS, backed by the repository's default Ktor contract. It assumes a Kotlin Multiplatform project and a backend reachable at `https://example.com`.

## 1. Add the mobile artifacts

The shared source set owns orchestration and transport. Platform source sets own the default platform client.

<!-- doc-example: id=site-mobile-quickstart-kotlin-1; owner=configuration; verify=consumer-compile; audience=consumer; source=documentation/consumer-smoke/defaults/build.gradle.kts.template#consumer-defaults-kmp-dependencies -->
```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("io.github.szijpeter:webauthn-client-flow:<version>")
            implementation("io.github.szijpeter:webauthn-client-ktor-kotlinx:<version>")
        }

        androidMain.dependencies {
            implementation("io.github.szijpeter:webauthn-client-defaults:<version>")
        }

        iosMain.dependencies {
            implementation("io.github.szijpeter:webauthn-client-defaults:<version>")
        }
    }
}
```

The public site renders `<version>` as **@@ARTIFACT_VERSION@@** from the latest stable repository tag. Keep every explicit KMP artifact on the same version.

## 2. Construct the platform clients

On Android, pass a context associated with the current UI host.

<!-- doc-example: id=site-mobile-quickstart-kotlin-2; owner=source; verify=platform-compile; audience=consumer; source=documentation/examples/src/androidMain/kotlin/dev/webauthn/documentation/examples/DefaultAndroidClientExample.kt#default-android-client -->
```kotlin
import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient
import dev.webauthn.json.WebAuthnJsonCodec

fun recommendedAndroidClient(context: Context): PasskeyClient = defaultPasskeyClient(context)

fun customCodecAndroidClient(
    context: Context,
    codec: WebAuthnJsonCodec,
): PasskeyClient = defaultPasskeyClient(context) {
    this.codec = codec
}
```

On iOS, use the default constructor unless your host needs to supply a specific presentation window.

<!-- doc-example: id=site-mobile-quickstart-kotlin-3; owner=source; verify=platform-compile; audience=consumer; source=documentation/examples/src/iosMain/kotlin/dev/webauthn/documentation/examples/DefaultIosClientExample.kt#default-ios-client -->
```kotlin
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient
import dev.webauthn.client.ios.PasskeyPresentationAnchorProvider

fun recommendedIosClient(): PasskeyClient = defaultPasskeyClient()

fun anchoredIosClient(
    presentationAnchorProvider: PasskeyPresentationAnchorProvider,
): PasskeyClient = defaultPasskeyClient(presentationAnchorProvider)
```

## 3. Connect the default backend contract

The backend start response supplies WebAuthn options. The platform prompt returns a signed response. The finish request sends that response back for authoritative server validation.

<!-- doc-example: id=site-mobile-quickstart-kotlin-4; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/KtorClientExample.kt#kotlinx-ktor-backend -->
```kotlin
suspend fun authenticateWithDefaultContract(
    httpClient: HttpClient,
    passkeyClient: PasskeyClient,
    expectedOrigin: String,
): CeremonyResult<DefaultPasskeyFinishResult> {
    val backend = KotlinxKtorPasskeyBackend(
        httpClient = httpClient,
        endpointBase = "https://example.com",
    )
    return PasskeyFlow(passkeyClient).signIn(
        input = AuthenticationStartPayload(
            rpId = "example.com",
            origin = expectedOrigin,
            userName = "alice",
        ),
        backend = backend.authenticationBackend(),
    )
}
```

Imports are omitted from the focused excerpt; the source-linked example is compiled in this repository.
Pass the HTTPS relying-party origin for iOS. On Android, pass the `android:apk-key-hash:...` origin
derived from the installed app's signing certificate; do not reuse the web origin.

## 4. Handle results deliberately

Do not convert every outcome other than success into “passkey failed.” Preserve cancellation, invalid options, transport failures, platform failures, and server rejection as distinct product states. See the [result and error model](../reference/results.md).

## 5. Prove the complete path

- Registration start and finish succeed for a new account.
- Authentication start and finish succeed for that credential.
- User cancellation returns control without an error loop.
- A stale or replayed ceremony is rejected by the backend.
- Android and iOS association files match the actual signed app identities.
- Provider-backed physical-device testing covers the production RP ID.

Continue with the [full sample](full-stack.md) before adapting this into production code.
