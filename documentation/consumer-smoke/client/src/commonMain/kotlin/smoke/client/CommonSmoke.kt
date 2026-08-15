package smoke.client

import dev.webauthn.network.kotlinx.KotlinxKtorPasskeyBackend

fun commonSmoke(backend: KotlinxKtorPasskeyBackend): String = backend::class.simpleName.orEmpty()
