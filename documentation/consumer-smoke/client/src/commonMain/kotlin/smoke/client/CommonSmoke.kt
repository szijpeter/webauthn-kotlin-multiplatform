package smoke.client

import dev.webauthn.network.KtorPasskeyRoutes

fun commonSmoke(routes: KtorPasskeyRoutes = KtorPasskeyRoutes()): String = routes.registerOptionsPath
