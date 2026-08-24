# Migration from removed client APIs

Release `v0.4.0` replaced controller-owned client state with explicit platform, flow, transport, and application layers. The new shape makes trust and lifecycle ownership visible but requires coordinated source changes.

| Removed integration | Replacement |
| --- | --- |
| `webauthn-client-android` / `webauthn-client-ios` | `webauthn-client-platform`, normally constructed via `webauthn-client-defaults` |
| `webauthn-network-ktor-client` | `webauthn-client-ktor-kotlinx`, or neutral `webauthn-client-ktor` with a custom codec |
| `PasskeyController` | `PasskeyFlow` plus application-owned UI state |
| `PasskeyServerClient` | `RegistrationBackend` and `AuthenticationBackend` |
| `rememberPasskeyController` | `rememberPasskeyFlow` plus product state |
| `PasskeyFinishResult` | Default-contract result or your own backend output type |
| Parsed platform responses | `RawRegistrationResponse` and `RawAuthenticationResponse` |

## Migration order

1. Align all artifacts to the same release and replace removed coordinates.
2. Construct `PasskeyClient` through platform defaults.
3. Move start and finish HTTP calls into backend contract implementations.
4. Replace controller presentation state with screen/view-model state.
5. Map `CeremonyFailure.Platform` and `AlreadyInProgress` deliberately.
6. Let backend and callback exceptions follow your application policy.
7. Update the server finish boundary to accept raw responses and derive signed client data internally.
8. Run registration and authentication across each supported app identity and backend version.

## Behavioral differences to test

- Concurrent calls are rejected rather than queued.
- User cancellation stays a typed platform failure.
- Backend exceptions are not automatically converted into a library transport error.
- Opaque backend continuation state must survive start → finish unchanged.
- The application owns loading, prompt, finishing, navigation, and retry state.

For release details, read the [changelog](../project/changelog.md).
