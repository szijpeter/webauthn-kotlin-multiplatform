# samples:compose-passkey-ios

Ready-to-run iOS host app for the shared `samples:compose-passkey` Compose UI.

Use this sample when you want to run the passkey demo on a connected iPhone from Xcode with minimal setup.

## What is included

- A committed Xcode app project (`ComposePasskeyIos.xcodeproj`).
- SwiftUI app shell that mounts Kotlin `MainViewController()` from `samples:compose-passkey`.
- Build phase script that runs `:samples:compose-passkey:embedAndSignAppleFrameworkForXcode`.

## Quick run on device (free Apple account)

This path verifies the app is runnable on a real phone without a paid Apple Developer Program membership.

1. Open Xcode project:

```bash
open samples/compose-passkey-ios/ComposePasskeyIos.xcodeproj
```

2. In Xcode target settings (`ComposePasskeyIos`):
- Set a unique bundle id (for example `dev.webauthn.samples.composepasskey.ios.<yourname>`).
- Set `Signing & Capabilities` to your personal team.
- Keep automatic signing enabled.

3. Select your connected iPhone and run.

Expected result:
- App installs and launches.
- Compose UI renders.
- Debug panel shows config and platform capability logs.

Note:
- Real passkey register/sign-in may fail on free accounts if Associated Domains entitlement/domain association is unavailable.

## Full passkey E2E path (Associated Domains capable setup)

Use this path when your signing setup supports Associated Domains and you want real register/sign-in success.

1. Start backend with tunnel helper:

```bash
IOS_TEAM_ID=<TEAM_ID> \
IOS_BUNDLE_ID=<BUNDLE_ID> \
./samples/backend-ktor/start-server.sh
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
- `PasskeyDemo` logs appear in Xcode console and in-app log panel.

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
  - Run from repo root and ensure `samples:compose-passkey` iOS framework targets are configured.
- Register/Sign In fails with domain/association style errors:
  - Check `IOS_APP_ID` alignment and `webcredentials:<domain>` entry.
  - Verify backend serves `/.well-known/apple-app-site-association` for the exact HTTPS domain.
- Simulator works but device passkey flow fails:
  - This is usually signing/entitlement/domain mismatch rather than Compose wiring.

## Maintaining this project

If `project.yml` changes, regenerate the Xcode project:

```bash
xcodegen generate --spec samples/compose-passkey-ios/project.yml
```
