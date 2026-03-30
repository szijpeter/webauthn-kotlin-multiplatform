package dev.webauthn.samples.composepasskey.navigation

import androidx.navigation3.runtime.NavKey
import androidx.savedstate.serialization.SavedStateConfiguration
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

internal val NavBackStackConfig: SavedStateConfiguration = SavedStateConfiguration {
    serializersModule = SerializersModule {
        polymorphic(NavKey::class) {
            subclass(AppRoute.Auth::class, AppRoute.Auth.serializer())
            subclass(AppRoute.LoggedIn::class, AppRoute.LoggedIn.serializer())
        }
    }
}
