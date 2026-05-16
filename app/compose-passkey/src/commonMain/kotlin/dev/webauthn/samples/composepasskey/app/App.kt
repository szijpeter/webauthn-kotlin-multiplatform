package dev.webauthn.samples.composepasskey.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.samples.composepasskey.app.di.sampleAppModules
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.network.DemoPasskeyServerClient
import dev.webauthn.samples.composepasskey.data.network.normalizedEndpoint
import dev.webauthn.samples.composepasskey.data.network.rememberPlatformHttpClient
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import kotlinx.coroutines.launch
import org.koin.compose.KoinApplication
import org.koin.core.logger.Level
import org.koin.dsl.koinConfiguration

@Composable
fun App() {
    val scope = rememberCoroutineScope()
    val debugLogs = remember { DebugLogStore() }
    val httpLogSink: (String) -> Unit = remember(scope, debugLogs) {
        { line -> scope.launch { debugLogs.d("http", line) } }
    }
    val httpClient = rememberPlatformHttpClient(onLogLine = httpLogSink)
    val config = remember { PasskeyDemoConfig() }
    val passkeyClient = rememberPasskeyClient()
    val serverClient: DemoPasskeyServerClient = remember(httpClient, config.endpointBase) {
        KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
        )
    }

    val modules = remember(config, debugLogs, passkeyClient, serverClient) {
        sampleAppModules(
            config = config,
            debugLogs = debugLogs,
            passkeyClient = passkeyClient,
            serverClient = serverClient,
        )
    }
    val koinConfig = remember(modules) {
        koinConfiguration {
            modules(modules)
        }
    }

    KoinApplication(
        configuration = koinConfig,
        logLevel = Level.INFO,
    ) {
        SampleAppRoot()
    }
}
