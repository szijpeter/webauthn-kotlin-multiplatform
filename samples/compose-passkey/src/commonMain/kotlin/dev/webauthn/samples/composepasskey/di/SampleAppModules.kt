package dev.webauthn.samples.composepasskey.di

import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.InMemoryPrfSaltStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.PrfSaltStore
import dev.webauthn.samples.composepasskey.navigation.AppRoute
import dev.webauthn.samples.composepasskey.vm.AuthViewModel
import org.koin.core.annotation.KoinExperimentalAPI
import org.koin.core.module.dsl.viewModel
import org.koin.core.module.Module
import org.koin.dsl.module
import org.koin.dsl.navigation3.navigation

@OptIn(KoinExperimentalAPI::class)
internal fun sampleAppModules(
    config: PasskeyDemoConfig,
    debugLogs: DebugLogStore,
): List<Module> {
    return listOf(
        module {
            single<PasskeyDemoConfig> { config }
            single<DebugLogStore> { debugLogs }
            single<PrfSaltStore> { InMemoryPrfSaltStore() }

            viewModel {
                AuthViewModel(
                    config = get(),
                    debugLogs = get(),
                    saltStore = get(),
                )
            }

            navigation<AppRoute.Auth> {
                dev.webauthn.samples.composepasskey.ui.routes.AuthRoute()
            }
            navigation<AppRoute.LoggedIn> {
                dev.webauthn.samples.composepasskey.ui.routes.LoggedInRoute()
            }
        },
    )
}
