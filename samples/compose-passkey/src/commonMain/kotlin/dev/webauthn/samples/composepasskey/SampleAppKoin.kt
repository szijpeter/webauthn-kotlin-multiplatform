package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyClient
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.samples.composepasskey.di.sampleAppModules
import org.koin.core.context.startKoin
import org.koin.mp.KoinPlatform

internal fun initializeSampleAppKoin(passkeyClient: PasskeyClient) {
    if (KoinPlatform.getKoinOrNull() != null) {
        return
    }

    val debugLogs = DebugLogStore()
    val config = PasskeyDemoConfig()
    val httpClient = createPlatformHttpClient { line ->
        debugLogs.d(source = "http", message = line)
    }
    val serverClient = KtorPasskeyServerClient(
        httpClient = httpClient,
        endpointBase = config.endpointBase.normalizedEndpoint(),
    )

    startKoin {
        modules(
            sampleAppModules(
                passkeyClient = passkeyClient,
                serverClient = serverClient,
                config = config,
                debugLogs = debugLogs,
            ),
        )
    }
}

internal fun requireSampleAppKoinInitialization() {
    check(KoinPlatform.getKoinOrNull() != null) {
        "Sample app Koin is not initialized. Call initializeComposePasskeySampleAppKoin(...) before rendering App()."
    }
}
