# webauthn-serialization-kotlinx

Audience: teams mapping wire DTOs to typed WebAuthn models with kotlinx.serialization.

Use this module when you receive or emit JSON/CBOR payloads and want strict conversion into `webauthn-model` types.

```kotlin
import dev.webauthn.serialization.WebAuthnDtoMapper

val result = WebAuthnDtoMapper.toModel(dto)
val dto = WebAuthnDtoMapper.fromModel(model)
```

Choose this over `webauthn-model` alone when you need DTOs, mappers, or authenticated data parsing helpers.

Status: beta, with strict mapper validation and CBOR/COSE handling.
