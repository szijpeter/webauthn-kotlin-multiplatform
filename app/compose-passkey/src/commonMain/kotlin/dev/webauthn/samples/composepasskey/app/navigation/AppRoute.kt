package dev.webauthn.samples.composepasskey.app.navigation

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

@Serializable
internal sealed interface AppRoute : NavKey {
    @Serializable
    data object Auth : AppRoute

    @Serializable
    data object Main : AppRoute
}
