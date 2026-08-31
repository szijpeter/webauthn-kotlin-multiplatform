# Mobile production checklist

Use this as a release gate for each application identity and relying-party environment. A green library build is necessary but insufficient.

## Shared client and product behavior

- [ ] All WebAuthn options come from an authenticated or intentionally anonymous backend start ceremony.
- [ ] The backend—not the app—validates challenges, RP ID, origins, signatures, counters, and policy.
- [ ] Registration and authentication prevent duplicate concurrent submissions.
- [ ] User cancellation is a normal product outcome, distinct from platform or server failure.
- [ ] Coroutine cancellation propagates instead of being swallowed.
- [ ] Logs and analytics exclude raw WebAuthn response bodies, PRF output, keys, and session secrets.
- [ ] Timeouts, offline behavior, retry rules, and stale ceremony state are visible and tested.
- [ ] Optional extensions have capability checks and explicit fallbacks.

## Android

- [ ] Production package name and signing certificate fingerprint match live Digital Asset Links.
- [ ] Every distributed signing identity has been tested intentionally.
- [ ] Credential Manager provider dependency and environment are documented.
- [ ] A screen-lock-enabled physical device completes registration and authentication.
- [ ] App backgrounding, Activity recreation, and process/lifecycle interruptions are tested.

## iOS

- [ ] The signed app contains the intended `webcredentials` entitlement.
- [ ] The live association response matches the team and bundle application identifier.
- [ ] The provisioning profile and deployed domain agree with the release build.
- [ ] Presentation anchoring works for every supported scene/window configuration.
- [ ] Physical devices complete registration and authentication with production-like association.
- [ ] Native Swift apps pin a versioned release and resolve the checksum-pinned XCFramework from that tag.
- [ ] PRF sessions are accepted only after backend verification and are cleared on rejection, sign-out, and lifecycle end.
- [ ] The generated Xcode privacy report is reviewed for the complete application dependency graph.

## Cross-system rollout

- [ ] RP ID and allowed origins are reviewed as security policy, not environment strings copied from mobile.
- [ ] Ceremony state is one-time, bounded, and consumed atomically.
- [ ] Credential lookup and account linking cannot be confused across tenants or users.
- [ ] Observability separates client cancellation, provider failure, transport failure, and server rejection without exposing secrets.
- [ ] Rollback and compatibility behavior are known for the previous mobile and backend versions.

Continue with the independent [backend production checklist](../backend/production.md).
