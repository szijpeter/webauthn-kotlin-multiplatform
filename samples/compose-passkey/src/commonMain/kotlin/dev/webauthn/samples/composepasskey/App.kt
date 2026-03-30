package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.samples.composepasskey.di.sampleAppModules
import kotlinx.coroutines.launch
import org.koin.compose.KoinApplication
import org.koin.core.logger.Level
import org.koin.dsl.koinConfiguration

@Composable
fun App() {
    val scope = rememberCoroutineScope()
    val debugLogs = remember { DebugLogStore() }
    val httpLogSink: (String) -> Unit = remember(scope, debugLogs) {
        { line ->
            scope.launch {
                debugLogs.d(source = "http", message = line)
            }
        }
    }
    val httpClient = rememberPlatformHttpClient(onLogLine = httpLogSink)
    val config = remember { PasskeyDemoConfig() }
    val passkeyClient = ComposePasskeySampleOverrides.passkeyClientOverride ?: rememberPasskeyClient()
    val serverClient = ComposePasskeySampleOverrides.serverClientOverride ?: remember(httpClient, config.endpointBase) {
        KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
        )
    }

    DisposableEffect(httpClient) {
        onDispose {
            httpClient.close()
        }
    }

    val modules = remember(passkeyClient, serverClient, config, debugLogs) {
        sampleAppModules(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
            config = config,
            debugLogs = debugLogs,
        )
    }
    val koinConfig = remember(modules) {
        koinConfiguration {
            modules(modules)
        }
    }

    key(modules) {
        KoinApplication(
            configuration = koinConfig,
            logLevel = Level.INFO,
        ) {
            SampleAppRoot()
        }
    }
}
