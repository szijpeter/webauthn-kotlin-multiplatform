package dev.webauthn.samples.composepasskey.data.network

internal fun String.normalizedEndpoint(): String {
    return trim().trimEnd('/')
}

internal fun resolveDefaultRpId(endpointBase: String, configuredRpId: String): String {
    val candidate = configuredRpId.trim()
    val endpointHost = endpointBase.endpointHost()
    val shouldReplaceLocalhost =
        candidate.equals("localhost", ignoreCase = true) &&
            endpointHost != null &&
            endpointHost != "localhost" &&
            endpointHost != "127.0.0.1"
    return when {
        candidate.isNotEmpty() && !shouldReplaceLocalhost -> candidate
        endpointHost != null -> endpointHost
        candidate.isNotEmpty() -> candidate
        else -> "localhost"
    }
}

internal fun resolveDefaultOrigin(rpId: String, configuredOrigin: String): String {
    val candidate = configuredOrigin.trim()
    if (
        candidate.isNotEmpty() &&
        !candidate.equals("https://localhost", ignoreCase = true)
    ) {
        return candidate
    }

    val normalizedRpId = rpId.trim()
    val derived = if (normalizedRpId.isNotEmpty()) "https://$normalizedRpId" else null
    return derived ?: candidate.ifEmpty { "https://localhost" }
}

private fun String.endpointHost(): String? {
    val trimmed = trim()
    if (trimmed.isEmpty()) return null

    val noScheme = trimmed.substringAfter("://", trimmed)
    val authority = noScheme
        .substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
    if (authority.isEmpty()) return null

    return authority.substringBefore(':').ifBlank { null }
}
