package dev.webauthn.samples.passkeycli

import dev.webauthn.model.Base64UrlBytes
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CliParserTest {
    @Test
    fun parseRegister_usesDefaultsAndGeneratedUserHandle() {
        val parser = CliParser(cwd = createTempDirectory(prefix = "passkey-cli-defaults"))

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
        assertEquals("python3", invocation.common.pythonBinary)
        assertEquals("alice", invocation.userDisplayName)
        assertEquals(
            Base64UrlBytes.fromBytes("alice".encodeToByteArray()).encoded(),
            invocation.userHandle,
        )
    }

    @Test
    fun parseDoctor_acceptsCommonOptions() {
        val parser = CliParser(cwd = createTempDirectory(prefix = "passkey-cli-doctor"))

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
        val parser = CliParser(cwd = createTempDirectory(prefix = "passkey-cli-unknown"))

        assertFailsWith<CliUsageException> {
            parser.parse(arrayOf("unknown-cmd"))
        }
    }

    @Test
    fun parseRegister_prefersModuleLocalVenvPython_whenPresent() {
        val moduleDir = createTempDirectory(prefix = "passkey-cli-module")
        val venvPython = moduleDir
            .resolve(".venv")
            .resolve("bin")
            .createDirectories()
            .resolve("python")
        venvPython.writeText("#!/usr/bin/env python3\n")
        val parser = CliParser(cwd = moduleDir)

        val invocation = parser.parse(
            arrayOf(
                "register",
                "--user-name",
                "alice",
            ),
        )

        assertTrue(invocation is CliInvocation.Register)
        assertEquals(venvPython.toString(), invocation.common.pythonBinary)
    }
}
