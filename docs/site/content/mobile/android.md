# Android integration

The Android client uses Credential Manager. The published client libraries support the generated [platform support matrix](../reference/platform-support.md); successful ceremonies additionally require a usable credential provider, device security, app identity association, and a foreground-capable host.

## Host responsibilities

1. Supply an `Activity` or a context from which the default client can resolve the foreground `Activity`.
2. Invoke passkey actions from the foreground UI and preserve coroutine cancellation.
3. Include and configure the Credential Manager provider appropriate to your distribution environment.
4. Serve Digital Asset Links for the exact package name and signing certificate fingerprint.
5. Test every signing identity you ship: debug, internal, and production can have different fingerprints.

!!! warning "Origin is derived from the signed app"
    Credential Manager represents an Android application with an `android:apk-key-hash:...` origin derived from its signing certificate. Do not hard-code a web origin as if the Android app were a browser.

## Digital Asset Links

Serve `https://<rp-id>/.well-known/assetlinks.json` with a statement that matches the installed package and signing certificate. HTTPS behavior, content, redirects, cache headers, and deployment timing are part of the production integration—not library configuration.

## Provider-backed verification

An emulator or device needs:

- a supported Android version for the features you use;
- a configured screen lock;
- a passkey-capable provider and account;
- Google Play services when you use the Play Services provider;
- network access to the exact production-like backend and association domain.

Compilation and host-unit tests prove encoding, mapping, and control-flow behavior. They do not prove that a provider will display or accept a prompt.

## Common Android failures

| Symptom | First evidence to inspect | Likely boundary |
| --- | --- | --- |
| No credential provider | Device accounts, provider dependency, Play-enabled system image | Host/runtime setup |
| Domain or origin rejected | Installed signing fingerprint and live `assetlinks.json` | App association |
| Prompt cannot launch | Foreground Activity/context and lifecycle state | Host integration |
| Local backend unreachable | Emulator host routing, local-network permission, TLS | Network environment |
| User cancellation shown as error | Result mapping and UI state transition | Product behavior |

Use [Mobile troubleshooting](troubleshooting.md) for a boundary-first diagnostic path.
