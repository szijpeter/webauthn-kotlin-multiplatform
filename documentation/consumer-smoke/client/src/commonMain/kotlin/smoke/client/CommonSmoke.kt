package smoke.client

import dev.webauthn.network.KtorPasskeyServerClient

fun commonSmoke(client: KtorPasskeyServerClient): String = client::class.simpleName.orEmpty()
