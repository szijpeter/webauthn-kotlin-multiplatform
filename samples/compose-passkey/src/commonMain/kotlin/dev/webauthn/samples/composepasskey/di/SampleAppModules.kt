package dev.webauthn.samples.composepasskey.di

import dev.webauthn.client.PasskeyClient
import dev.webauthn.samples.composepasskey.DemoPasskeyServerClient
import dev.webauthn.samples.composepasskey.DebugLogStore
import dev.webauthn.samples.composepasskey.InMemoryPrfSaltStore
import dev.webauthn.samples.composepasskey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.PrfSaltStore
import dev.webauthn.samples.composepasskey.navigation.AppRoute
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import dev.webauthn.samples.composepasskey.ui.routes.AuthRoute
import dev.webauthn.samples.composepasskey.ui.routes.LoggedInRoute
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
    passkeyClient: PasskeyClient,
    serverClient: DemoPasskeyServerClient,
): List<Module> {
    return listOf(
        module {
            single<PasskeyDemoConfig> { config }
            single<DebugLogStore> { debugLogs }
            single<PasskeyClient> { passkeyClient }
            single<DemoPasskeyServerClient> { serverClient }
            single<AppSessionStore> { AppSessionStore() }
            single<PrfSaltStore> { InMemoryPrfSaltStore() }

            viewModel {
                LoggedInViewModel(
                    config = get(),
                    debugLogs = get(),
                    sessionStore = get(),
                    saltStore = get(),
                    passkeyClient = get(),
                    serverClient = get(),
                )
            }

            navigation<AppRoute.Auth> {
                AuthRoute()
            }
            navigation<AppRoute.LoggedIn> {
                LoggedInRoute()
            }
        },
    )
}
