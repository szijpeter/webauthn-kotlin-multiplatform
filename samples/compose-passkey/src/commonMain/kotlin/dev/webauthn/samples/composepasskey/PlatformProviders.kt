package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.Composable
import io.ktor.client.HttpClient

@Composable
public expect fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient
