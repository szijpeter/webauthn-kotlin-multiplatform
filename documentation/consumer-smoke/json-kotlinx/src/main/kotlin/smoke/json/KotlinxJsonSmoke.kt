package smoke.json

import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec
import kotlinx.serialization.json.Json

fun codecFromPublishedArtifact(): KotlinxWebAuthnJsonCodec =
    KotlinxWebAuthnJsonCodec(
        Json {
            ignoreUnknownKeys = true
        },
    )
