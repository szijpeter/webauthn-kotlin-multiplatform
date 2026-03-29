package dev.webauthn.samples.composepasskey.di

import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.InMemoryPrfSaltStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.PrfCryptoDemoController
import dev.webauthn.samples.composepasskey.PrfSaltStore
import dev.webauthn.samples.composepasskey.navigation.AppRoute
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import dev.webauthn.samples.composepasskey.vm.AuthViewModel
import dev.webauthn.samples.composepasskey.vm.LoggedInViewModel
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
            single<AppSessionStore> { AppSessionStore() }
            single<PrfSaltStore> { InMemoryPrfSaltStore() }

            factory<PrfCryptoDemoController> {
                PrfCryptoDemoController(
                    passkeyClient = get(),
                    serverClient = get(),
                    saltStore = get(),
                )
            }

            viewModel {
                AuthViewModel(
                    config = get(),
                    debugLogs = get(),
                    sessionStore = get(),
                )
            }
            viewModel {
                LoggedInViewModel(
                    passkeyClient = get(),
                    config = get(),
                    debugLogs = get(),
                    sessionStore = get(),
                    prfDemo = get(),
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
