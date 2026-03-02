package dev.webauthn.samples.composepasskey

import co.touchlab.kermit.Logger

public interface PasskeyDemoDiagnostics {
    public fun trace(
        event: String,
        fields: Map<String, String> = emptyMap(),
    )

    public fun error(
        event: String,
        message: String,
        throwable: Throwable? = null,
        fields: Map<String, String> = emptyMap(),
    )
}

public class KermitPasskeyDemoDiagnostics(
    private val logger: Logger = Logger.withTag("PasskeyDemo"),
) : PasskeyDemoDiagnostics {
    override fun trace(
        event: String,
        fields: Map<String, String>,
    ) {
        val output = formatEvent(event = event, fields = fields)
        logger.d { output }
    }

    override fun error(
        event: String,
        message: String,
        throwable: Throwable?,
        fields: Map<String, String>,
    ) {
        val output = formatEvent(
            event = event,
            fields = fields + mapOf("message" to message),
        )
        logger.e(throwable) { output }
    }
}

public val DefaultPasskeyDemoDiagnostics: PasskeyDemoDiagnostics = KermitPasskeyDemoDiagnostics()

public fun sanitizeNetworkLogLine(line: String): String {
    var sanitized = line

    sanitized = sanitized.replace(SENSITIVE_JSON_FIELD_REGEX) { match ->
        val key = match.groups[1]?.value ?: ""
        val value = match.groups[2]?.value.orEmpty()
        "$key<redacted:${value.length}>\""
    }

    sanitized = sanitized.replace(SENSITIVE_QUERY_PARAM_REGEX) { match ->
        val key = match.groups[1]?.value ?: ""
        val value = match.groups[2]?.value.orEmpty()
        "$key=<redacted:${value.length}>"
    }

    return sanitized
}

private fun formatEvent(
    event: String,
    fields: Map<String, String>,
): String {
    val encodedFields = fields
        .entries
        .sortedBy { entry -> entry.key }
        .joinToString(separator = " ") { entry ->
            "${entry.key}=${sanitizeNetworkLogLine(entry.value)}"
        }

    return if (encodedFields.isBlank()) {
        event
    } else {
        "$event $encodedFields"
    }
}

private val SENSITIVE_JSON_FIELD_REGEX = Regex(
    pattern = "(\"(?:challenge|clientDataJSON|clientDataJson|attestationObject|authenticatorData|signature|rawId|id|userHandle|credentialId)\"\\s*:\\s*\")([^\"]+)",
    options = setOf(RegexOption.IGNORE_CASE),
)

private val SENSITIVE_QUERY_PARAM_REGEX = Regex(
    pattern = "(challenge|clientDataJSON|clientDataJson|attestationObject|authenticatorData|signature|rawId|id|userHandle|credentialId|userId)=([^&\\s]+)",
    options = setOf(RegexOption.IGNORE_CASE),
)
