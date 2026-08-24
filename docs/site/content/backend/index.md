# Ktor backend quickstart

The JVM backend is the verification authority. It creates challenges and WebAuthn options, preserves one-time ceremony state, validates the signed response, and updates credential state. Mobile clients only carry options and responses across that boundary.

## 1. Add the coordinated server stack

The BOM aligns JVM artifacts. The stack below supplies ceremony services, JVM cryptography, Ktor routes, and Exposed-backed stores.

<!-- doc-example: id=site-backend-kotlin-1; owner=configuration; verify=consumer-compile; audience=consumer; source=documentation/consumer-smoke/server/build.gradle.kts.template#consumer-server-dependencies -->
```kotlin
dependencies {
    implementation(platform("io.github.szijpeter:webauthn-bom:<version>"))
    implementation("io.github.szijpeter:webauthn-server-core-jvm")
    implementation("io.github.szijpeter:webauthn-server-jvm-crypto")
    implementation("io.github.szijpeter:webauthn-server-ktor")
    implementation("io.github.szijpeter:webauthn-server-store-exposed")
}
```

## 2. Construct services and stores

`RegistrationService` and `AuthenticationService` share challenge, credential, and user-account store contracts. Use in-memory implementations only for development and tests. A multi-instance production service needs durable stores with atomic one-time ceremony consumption.

The services derive challenge, origin, and ceremony type from the exact signed `clientDataJSON` carried in the raw response. Custom transport code must not inject separate trusted claims for those values.

## 3. Install the default routes

<!-- doc-example: id=site-backend-kotlin-2; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/KtorServerExample.kt#ktor-routes -->
```kotlin
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.ktor.installWebAuthnRoutes
import io.ktor.server.application.Application

fun Application.installPasskeyRoutes(
    registrationService: RegistrationService,
    authenticationService: AuthenticationService,
) {
    installWebAuthnRoutes(registrationService, authenticationService)
}
```

The routes expose the [default endpoint contract](default-contract.md). Put your authentication/session policy, rate limits, request limits, TLS termination, and operational controls around them.

## 4. Connect the mobile client

Use `KotlinxKtorPasskeyBackend` in shared mobile code when the default contract fits. Otherwise implement the generic `RegistrationBackend` and `AuthenticationBackend` interfaces and keep their continuation state opaque.

## Readiness boundary

Before production, complete the [ceremony state and storage](storage.md), [mobile-to-server trust boundary](../concepts/trust-boundary.md), and [backend production](production.md) reviews. Running the sample provides integration evidence, not a security review of your account and deployment policy.
