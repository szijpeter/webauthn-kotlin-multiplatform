package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
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
    val passkeyClient = rememberPasskeyClient()
    val serverClient = remember(httpClient, config.endpointBase) {
        KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
        )
    }
    val runtimeDependencies = remember(passkeyClient, serverClient) {
        AuthRuntimeDependencies(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
        )
    }

    DisposableEffect(httpClient) {
        onDispose {
            httpClient.close()
        }
    }

    val modules = remember(config, debugLogs) {
        sampleAppModules(
            config = config,
            debugLogs = debugLogs,
        )
    }
    val koinConfig = remember(modules) {
        koinConfiguration {
            modules(modules)
        }
    }

    CompositionLocalProvider(LocalAuthRuntimeDependencies provides runtimeDependencies) {
        KoinApplication(
            configuration = koinConfig,
            logLevel = Level.INFO,
        ) {
            SampleAppRoot()
        }
    }
}
