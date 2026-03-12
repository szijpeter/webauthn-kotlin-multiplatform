# webauthn-bom

Audience: consumers who want one aligned version across the published WebAuthn Kotlin Multiplatform artifacts.

Use this BOM when you want Gradle to keep the module versions in sync.

```kotlin
dependencies {
    implementation(platform("io.github.szijpeter:webauthn-bom:<version>"))
    implementation("io.github.szijpeter:webauthn-server-core-jvm")
    implementation("io.github.szijpeter:webauthn-client-core")
}
```

Use this when you consume multiple published modules together. Skip it only if you intentionally manage versions yourself.

Status: release-train alignment artifact for the public surface.
