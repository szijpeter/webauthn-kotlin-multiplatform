package dev.webauthn.samples.composepasskey.app.di

import dev.webauthn.client.PasskeyClient
import dev.webauthn.samples.composepasskey.app.navigation.AppRoute
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyServerClient
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.prf.InMemoryPrfSaltStore
import dev.webauthn.samples.composepasskey.domain.prf.PrfSaltStore
import dev.webauthn.samples.composepasskey.ui.auth.AuthRoute
import dev.webauthn.samples.composepasskey.ui.main.MainRoute
import dev.webauthn.samples.composepasskey.ui.main.MainViewModel
import org.koin.core.annotation.KoinExperimentalAPI
import org.koin.core.module.Module
import org.koin.core.module.dsl.viewModel
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
                MainViewModel(
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
            navigation<AppRoute.Main> {
                MainRoute()
            }
        },
    )
}
