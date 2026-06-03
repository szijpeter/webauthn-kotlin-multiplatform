# webauthn-client-android

Android platform bridge for passkey operations using Credential Manager.

## What it provides

- `AndroidPasskeyClient`
- `AndroidRestoreCredentialClient`
- `AndroidCredentialSignalClient`
- Android `PasskeyClient` implementation for registration and authentication ceremonies
- Android Restore Credentials helpers for system-managed restore keys
- Android Credential Manager signal helpers for provider-side passkey consistency hints
- A platform adapter designed to be orchestrated by `webauthn-client-core`
- Capabilities reporting via `PasskeyCapabilities.supported: Set<PasskeyCapability>` with key-based lookup

## When to use

Use this in Android apps that need real platform passkey prompts and credentials.

## How to use

```kotlin
import dev.webauthn.client.android.AndroidPasskeyClient

val client = AndroidPasskeyClient(context)
```

Real-world scenario: your shared app logic drives ceremony flow in `PasskeyController`, while `AndroidPasskeyClient` performs the platform call into Credential Manager.

For Android automatic passkey upgrades after a successful password or other non-passkey sign-in,
call the shared create overload with conditional options:

```kotlin
import dev.webauthn.client.PasskeyCreateOptions

val result = client.createCredential(
    options = creationOptions,
    createOptions = PasskeyCreateOptions.Conditional,
)
```

This maps to Credential Manager conditional create with immediately-available credentials preferred,
so providers can create the passkey opportunistically without blocking system UI.
If no enabled provider has an immediately available creation option, Credential Manager returns
`CreateCredentialNoCreateOptionException`; this bridge reports that as
`PasskeyClientError.Platform("No credential creation option found")`. Treat that as an expected
conditional-create no-op and continue the already-successful sign-in flow.

For seamless sign-in after app restore, create and retrieve system-managed restore credentials with
`AndroidRestoreCredentialClient`:

```kotlin
import dev.webauthn.client.android.AndroidRestoreCredentialClient

val restoreCredentials = AndroidRestoreCredentialClient(context)

restoreCredentials.createRestoreCredential(
    options = creationOptionsFromServer,
    isCloudBackupEnabled = true,
)

restoreCredentials.getRestoreCredential(requestOptionsFromServer)

restoreCredentials.clearRestoreCredential()
```

Create the restore credential after the user signs in, retrieve it during app-data restore or first
launch on a new device, and clear it when the user signs out.

For provider consistency after account or credential changes, use the Credential Manager Signal API
adapter:

```kotlin
import dev.webauthn.client.android.AndroidCredentialSignalClient

val signals = AndroidCredentialSignalClient(context)

signals.signalUnknownCredential(
    rpId = rpId,
    credentialId = staleCredentialId,
)

signals.signalAllAcceptedCredentialIds(
    rpId = rpId,
    userId = userHandle,
    credentialIds = currentCredentialIds,
)
```

Signal calls do not show UI. A successful result means Credential Manager accepted and dispatched
the signal to enabled providers; it does not guarantee a provider applied the update.

## How it fits

```mermaid
flowchart LR
    UI["Android UI"] --> CORE["webauthn-client-core controller"]
    CORE --> ANDROID["AndroidPasskeyClient"]
    ANDROID --> CM["Android Credential Manager"]
    CORE --> NET["PasskeyServerClient"]
```

## Pitfalls and limits

- This module is only the Android platform adapter; network and orchestration are separate concerns.
- Reported capabilities use the shared two-type model:
  - `PasskeyCapability.Extension(WebAuthnExtension.Prf)` when PRF is supported.
  - `PasskeyCapability.Extension(WebAuthnExtension.LargeBlob)` when largeBlob is supported.
  - `PasskeyCapability.PlatformFeature(PasskeyPlatformFeatureKeys.ConditionalCreate)` when conditional create can be requested.
  - `PasskeyCapability.PlatformFeature(PasskeyPlatformFeatureKeys.SecurityKey)` when cross-platform security keys are supported.
- Keep backend contract alignment with your chosen server client implementation.
- Conditional create should only run after a successful non-passkey sign-in or sign-up where an
  automatic passkey upgrade is appropriate; keep explicit registration flows on the default
  `createCredential(options)` path.
- Restore credentials use the same server-side WebAuthn registration and authentication processing
  as passkeys, but store them separately from user-managed passkeys. They are system-managed and
  should not appear on a passkey management page.
- Cloud backup for restore credentials is recommended. If you intentionally disable it, users who
  restore app data from cloud backup cannot use that local-only restore key for automatic sign-in.
- Signal API calls are best-effort provider hints. Continue to enforce credential/account state on
  the server even after a successful signal result.
- If the platform reports `RP ID cannot be validated`, verify:
  - RP ID and HTTPS origin/domain alignment.
  - `/.well-known/assetlinks.json` availability.
  - Android package name and signing SHA-256 fingerprint entries in that file.

## Status

Beta, thin Android bridge on top of shared client orchestration.
