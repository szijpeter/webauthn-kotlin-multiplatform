package dev.webauthn.samples.composepasskey

import io.ktor.client.HttpClient

expect fun createPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient

expect fun platformRuntimeHint(): String?
