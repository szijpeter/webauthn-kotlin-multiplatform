# Choose modules

Begin with the recommended composition, then move down a layer only when you need to replace a specific default. Each replacement adds an API and security contract that your application must own.

## Mobile decision table

| Need | Add | Avoid adding unless needed |
| --- | --- | --- |
| Shared start → prompt → finish orchestration | `webauthn-client-flow` | Direct platform-only orchestration in every host |
| Repository default HTTP/JSON contract | `webauthn-client-ktor-kotlinx` | Separate neutral codec artifacts |
| Recommended Android/iOS construction | `webauthn-client-defaults` | Manual bridge and codec composition |
| Compose lifecycle helpers | `webauthn-client-compose` | Treating the helper as product state management |
| Typed platform calls only | `webauthn-client-core` + `webauthn-client-platform` | Flow and Ktor layers |
| Custom JSON wrapper | `webauthn-client-json-core` + codec implementation | Built-in Kotlinx selection |
| PRF-derived application crypto | `webauthn-client-prf-crypto` | Extension-dependent UI without fallback |

Ktor client artifacts do not bundle an engine. Choose the engine appropriate to each target in your application.

## Backend decision table

| Need | Add |
| --- | --- |
| Typed JVM ceremony services | `webauthn-server-core-jvm` |
| Standard JVM verification implementations | `webauthn-server-jvm-crypto` |
| Default Ktor routes | `webauthn-server-ktor` |
| Exposed/JDBC store adapters | `webauthn-server-store-exposed` |
| FIDO metadata integration | `webauthn-attestation-mds` |

Use `webauthn-bom` to align JVM artifact versions. KMP source-set dependencies still require explicit aligned versions.

## Foundation modules

The core area separates public models, validation, protocol and binary parsing, JSON interfaces and implementations, cryptography interfaces, extension hooks, and runtime helpers. Most applications should not assemble those independently. They are intended for custom client/server stacks and library authors.

The generated [artifact catalog](../reference/modules.md) is built from each published module's README so the public list tracks the actual published-library configuration.
