# RP IDs, origins, and app association

The RP ID defines the relying-party scope for a credential. Origins identify the calling application context. Mobile platform association connects a signed app identity to the web domain that owns the RP.

## Web and mobile origins

A web origin is typically an HTTPS scheme, host, and port. Native mobile platforms represent application identity differently:

- Android uses an application origin derived from the installed package's signing certificate and validates domain association through Digital Asset Links.
- iOS uses the signed application identifier and Associated Domains, backed by an `apple-app-site-association` response.

The server must allow the exact origins appropriate to its clients. Do not accept arbitrary origins supplied in a start request merely because they came through your own app.

## Association files

| Platform | Path | Must match |
| --- | --- | --- |
| Android | `/.well-known/assetlinks.json` | Package name and signing certificate fingerprint |
| iOS | `/.well-known/apple-app-site-association` | Team identifier and bundle identifier |

Serve both over HTTPS from the RP domain. Verify the live response, redirect behavior, content, and caching. App Store signing, internal distribution, and debug builds can represent different application identities.

## Environment design

Prefer a clear RP and app-identity strategy for development, staging, and production. A localhost-only sample can prove flow wiring, but production association requires the deployed domain and the actual signed application. Avoid letting temporary tunnel domains become accidental credential scopes.
