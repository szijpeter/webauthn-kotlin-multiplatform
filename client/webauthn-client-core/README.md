# webauthn-client-core

Platform-neutral passkey operations and result/error contracts.

## What it provides

- `PasskeyClient` for typed platform ceremonies.
- `DefaultPasskeyClient` for shared raw-response interpretation and error mapping.
- `PasskeyResult`, `PasskeyClientError`, and capability contracts.

Use `webauthn-client-flow` when the application also needs start → prompt → finish orchestration.

## Status

Beta, with no transport, UI-state, or backend dependency.
