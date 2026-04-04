package dev.webauthn.samples.passkeycli

import dev.webauthn.model.Base64UrlBytes
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CliParserTest {
    @Test
    fun parseRegister_usesDefaultsAndGeneratedUserHandle() {
        val parser = CliParser(cwd = Path.of("/tmp/webauthn"))

        val invocation = parser.parse(
            arrayOf(
                "register",
                "--user-name",
                "alice",
            ),
        )

        assertTrue(invocation is CliInvocation.Register)
        assertEquals("http://127.0.0.1:8080", invocation.common.endpointBase)
        assertEquals("localhost", invocation.common.rpId)
        assertEquals("https://localhost", invocation.common.origin)
        assertEquals("alice", invocation.userDisplayName)
        assertEquals(
            Base64UrlBytes.fromBytes("alice".encodeToByteArray()).encoded(),
            invocation.userHandle,
        )
    }

    @Test
    fun parseDoctor_acceptsCommonOptions() {
        val parser = CliParser(cwd = Path.of("/tmp/webauthn"))

        val invocation = parser.parse(
            arrayOf(
                "doctor",
                "--python-bin",
                "/opt/homebrew/bin/python3",
                "--python-bridge",
                "/repo/samples/passkey-cli/scripts/fido2_bridge.py",
            ),
        )

        assertTrue(invocation is CliInvocation.Doctor)
        assertEquals("/opt/homebrew/bin/python3", invocation.common.pythonBinary)
        assertEquals("/repo/samples/passkey-cli/scripts/fido2_bridge.py", invocation.common.pythonBridgePath)
    }

    @Test
    fun parseUnknownCommand_throwsUsageException() {
        val parser = CliParser(cwd = Path.of("/tmp/webauthn"))

        assertFailsWith<CliUsageException> {
            parser.parse(arrayOf("unknown-cmd"))
        }
    }
}
