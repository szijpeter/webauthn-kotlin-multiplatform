# WebAuthn Refactor Landing Plan

This temporary execution map coordinates the client/server boundary landing. No release occurs
between checkpoints; it will be updated as the stack advances and deleted after the final landing.

| Checkpoint | Status | Scope |
| --- | --- | --- |
| 1 | Complete | Signed client-data trust boundary in HTTP finish routes |
| 2 | Complete | Raw models plus codec-neutral protocol and JSON foundation |
| 3 | Complete | Server-neutral finish boundary and signed-data ownership |
| 4 | In progress | Client/platform raw-response foundation and consolidated KMP platform module |
| 5 | In progress | Final state-free ceremony flow and Compose entry point |
| 6 | Pending | Optional Ktor client transport artifact |
| 7 | Pending | Default platform composition |
| 8 | Pending | Final stack integration and release readiness |

The earlier #222–#247 incremental PRs are retained as historical source material. This landing
series supersedes their intermediate topology where necessary, while preserving the intended
public behavior in reviewable checkpoints.

## Checkpoint 4 boundary

- `PasskeyClient` and platform bridges return raw WebAuthn responses.
- `webauthn-client-platform` owns Android Credential Manager and iOS AuthenticationServices adapters.
- JSON codecs are explicit dependencies of Android and JSON facades; Kotlinx is test-only there.
- Transport, flow, Ktor, and defaults composition remain out of this checkpoint.

## Checkpoint 5 boundary

- `webauthn-client-flow` exposes generic registration/authentication backends with opaque state.
- `PasskeyFlow` returns application output and only classifies platform failures and concurrency.
- Backend, platform-client, callback, and cancellation exceptions retain their original semantics.
- Compose can remember a flow, while the application owns presentation state and result mapping.
