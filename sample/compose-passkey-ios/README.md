# sample:compose-passkey-ios

Ready-to-run iOS host app for the shared `sample:compose-passkey` Compose UI.

Use this sample when you want to run the passkey demo on a connected iPhone from Xcode with minimal setup.

## What is included

- A committed Xcode app project (`ComposePasskeyIos.xcodeproj`).
- SwiftUI app shell that mounts Kotlin `MainViewController()` from `sample:compose-passkey`.
- Build phase script that runs `:sample:compose-passkey:embedAndSignAppleFrameworkForXcode`.
- Swift bridge for iOS credential signals using `ASCredentialDataManager` when running on iOS 26.2+.

## Quick run on device (free Apple account)

This path verifies the app is runnable on a real phone without a paid Apple Developer Program membership.

1. Open Xcode project:

```bash
open sample/compose-passkey-ios/ComposePasskeyIos.xcodeproj
```

2. In Xcode target settings (`ComposePasskeyIos`):
- Set a unique bundle id (for example `dev.webauthn.samples.composepasskey.ios.<yourname>`).
- Set `Signing & Capabilities` to your personal team.
- Keep automatic signing enabled.

3. Select your connected iPhone and run.

Expected result:
- App installs and launches.
- Compose UI renders with the `Auth` screen first (`Register` / `Sign In`).
- Signed-in debug logs remain hidden unless the title is double-tapped.

Note:
- Real passkey register/sign-in may fail on free accounts if Associated Domains entitlement/domain association is unavailable.

## Full passkey E2E path (Associated Domains capable setup)

Use this path when your signing setup supports Associated Domains and you want real register/sign-in success.

1. Start backend with tunnel helper:

```bash
IOS_TEAM_ID=<TEAM_ID> \
IOS_BUNDLE_ID=<BUNDLE_ID> \
./sample/backend-ktor/start-server.sh
```

2. Ensure app identity matches backend AASA config:
- Canonical value is `IOS_APP_ID`.
- If `IOS_APP_ID` is unset, backend derives it from `IOS_TEAM_ID.IOS_BUNDLE_ID`.
- `IOS_APP_ID` must match your signed app id (`<TEAM_ID>.<BUNDLE_ID>`).

3. In Xcode, add capability:
- `Signing & Capabilities` -> `Associated Domains`
- Add `webcredentials:<your-https-domain>` (the ngrok host from helper output).

4. Rebuild and run the iOS app.

Expected result:
- `Register` completes.
- `Sign In` completes.
- Signed-in extension demo screen is shown after successful sign-in.
- `PasskeyDemo` logs appear in Xcode console and in the hidden in-app debug sheet (title double-tap).
- On iOS 26.2+, the app reports the signed-in user name to AuthenticationServices through the Swift credential-signal bridge.

## iOS credential signal bridge

The shared Kotlin module exports `IosCredentialSignalBridge` because Kotlin/Native does not currently
expose Swift-only `ASCredentialDataManager` bindings under `platform.AuthenticationServices`.
`AuthenticationServicesCredentialSignalBridge` implements that protocol in Swift and is passed into
`MainViewController(...)` by the host app.

Availability expectations:

- iOS 26.2+: `reportPublicKeyCredentialUpdate(...)` is called after successful sign-in.
- Older iOS versions: the bridge reports unavailable and the sample logs that credential signals require iOS 26.2+.

## Environment variables used by the shared sample

Build-time values come from Gradle properties / env vars / `local.properties`:

- `WEBAUTHN_DEMO_ENDPOINT`
- `WEBAUTHN_DEMO_RP_ID`
- `WEBAUTHN_DEMO_ORIGIN`
- `WEBAUTHN_DEMO_USER_ID`
- `WEBAUTHN_DEMO_USER_NAME`

Backend iOS association identity:

- `IOS_APP_ID` (canonical)
- `IOS_TEAM_ID` (optional helper input)
- `IOS_BUNDLE_ID` (optional helper input)

## Troubleshooting

- Signing error about provisioning/profile:
  - Re-select your personal/team signing identity and unique bundle id.
- Build phase cannot find Gradle task:
  - Run from repo root and ensure `sample:compose-passkey` iOS framework targets are configured.
- Register/Sign In fails with domain/association style errors:
  - Check `IOS_APP_ID` alignment and `webcredentials:<domain>` entry.
  - Verify backend serves `/.well-known/apple-app-site-association` for the exact HTTPS domain.
- Simulator works but device passkey flow fails:
  - This is usually signing/entitlement/domain mismatch rather than Compose wiring.

## Maintaining this project

If `project.yml` changes, regenerate the Xcode project:

```bash
xcodegen generate --spec sample/compose-passkey-ios/project.yml
```
