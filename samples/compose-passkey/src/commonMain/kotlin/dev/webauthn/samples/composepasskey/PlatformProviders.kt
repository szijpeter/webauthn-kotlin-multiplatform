package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.Composable
import dev.webauthn.client.PasskeyClient
import io.ktor.client.HttpClient

@Composable
public expect fun rememberPlatformPasskeyClient(): PasskeyClient

@Composable
public expect fun rememberPlatformHttpClient(): HttpClient

public expect fun platformDefaultEndpointBase(): String

public expect fun platformDebugLog(tag: String, message: String, throwable: Throwable? = null)
