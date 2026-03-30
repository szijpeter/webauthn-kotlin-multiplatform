# webauthn-client-android

Android platform bridge for passkey operations using Credential Manager.

## What it provides

- `AndroidPasskeyClient`
- Android `PasskeyClient` implementation for registration and authentication ceremonies
- A platform adapter designed to be orchestrated by `webauthn-client-core`
- Capabilities reporting via `PasskeyCapabilities.supported: Set<PasskeyCapability>` with key-based lookup

## When to use

Use this in Android apps that need real platform passkey prompts and credentials.

## How to use

```kotlin
import dev.webauthn.client.android.AndroidPasskeyClient
import dev.webauthn.client.android.MutablePasskeyPromptContextProvider

val client = AndroidPasskeyClient(
    contextProvider = MutablePasskeyPromptContextProvider(context),
)
```

Real-world scenario: your shared app logic drives ceremony flow in `PasskeyController`, while `AndroidPasskeyClient` performs the platform call into Credential Manager.

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
  - `PasskeyCapability.PlatformFeature("securityKey")` when cross-platform security keys are supported.
- Keep backend contract alignment with your chosen server client implementation.
- If the platform reports `RP ID cannot be validated`, verify:
  - RP ID and HTTPS origin/domain alignment.
  - `/.well-known/assetlinks.json` availability.
  - Android package name and signing SHA-256 fingerprint entries in that file.

## Status

Beta, thin Android bridge on top of shared client orchestration.
