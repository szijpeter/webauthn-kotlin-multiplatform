package dev.webauthn.samples.composepasskey

import kotlin.test.Test
import kotlin.test.assertTrue

class PasskeyDemoDiagnosticsTest {
    @Test
    fun sanitize_network_log_line_redacts_sensitive_fields() {
        val line = """
            POST /register/verify body={"challenge":"abc123","clientDataJSON":"payload","signature":"sig123"} query=challenge=abc123&id=cred-1
        """.trimIndent()

        val sanitized = sanitizeNetworkLogLine(line)

        assertTrue(sanitized.contains("\"challenge\":\"<redacted:6>\""))
        assertTrue(sanitized.contains("\"clientDataJSON\":\"<redacted:7>\""))
        assertTrue(sanitized.contains("challenge=<redacted:6>"))
        assertTrue(sanitized.contains("id=<redacted:6>"))
    }
}
