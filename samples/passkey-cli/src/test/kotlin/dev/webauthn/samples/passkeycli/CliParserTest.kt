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
        assertEquals("http://localhost:8080", invocation.common.endpointBase)
        assertEquals("localhost", invocation.common.rpId)
        assertEquals("http://localhost:8080", invocation.common.origin)
        assertEquals(AuthenticatorMode.BROWSER, invocation.common.authenticatorMode)
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
                "--authenticator",
                "ctap",
            ),
        )

        assertTrue(invocation is CliInvocation.Doctor)
        assertEquals(AuthenticatorMode.CTAP, invocation.common.authenticatorMode)
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
    fun parseRegister_invalidAuthenticator_throwsUsageException() {
        val parser = CliParser(cwd = createTempDirectory(prefix = "passkey-cli-auth-mode"))

        assertFailsWith<CliUsageException> {
            parser.parse(
                arrayOf(
                    "register",
                    "--user-name",
                    "alice",
                    "--authenticator",
                    "magic",
                ),
            )
        }
    }

    @Test
    fun parseRegister_derivesRpIdAndOriginFromEndpoint_whenNotProvided() {
        val parser = CliParser(cwd = createTempDirectory(prefix = "passkey-cli-endpoint-defaults"))

        val invocation = parser.parse(
            arrayOf(
                "register",
                "--user-name",
                "alice",
                "--endpoint",
                "https://login.example.com:8443/base",
            ),
        )

        assertTrue(invocation is CliInvocation.Register)
        assertEquals("login.example.com", invocation.common.rpId)
        assertEquals("https://login.example.com:8443", invocation.common.origin)
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

    @Test
    fun parseRegister_usesLocalPropertiesDefaults_whenPresent() {
        val rootDir = createTempDirectory(prefix = "passkey-cli-local-properties")
        rootDir.resolve("local.properties").writeText(
            """
                WEBAUTHN_DEMO_ENDPOINT=https://sample.ngrok-free.app
                WEBAUTHN_DEMO_RP_ID=sample.ngrok-free.app
                WEBAUTHN_DEMO_ORIGIN=https://sample.ngrok-free.app
            """.trimIndent(),
        )
        val parserCwd = rootDir.resolve("samples/passkey-cli").createDirectories()
        val parser = CliParser(cwd = parserCwd)

        val invocation = parser.parse(
            arrayOf(
                "register",
                "--user-name",
                "alice",
            ),
        )

        assertTrue(invocation is CliInvocation.Register)
        assertEquals("https://sample.ngrok-free.app", invocation.common.endpointBase)
        assertEquals("sample.ngrok-free.app", invocation.common.rpId)
        assertEquals("https://sample.ngrok-free.app", invocation.common.origin)
    }

    @Test
    fun parseRegister_explicitEndpointDerivesRpIdAndOrigin_evenWithLocalProperties() {
        val rootDir = createTempDirectory(prefix = "passkey-cli-local-properties-endpoint-override")
        rootDir.resolve("local.properties").writeText(
            """
                WEBAUTHN_DEMO_ENDPOINT=https://sample.ngrok-free.app
                WEBAUTHN_DEMO_RP_ID=sample.ngrok-free.app
                WEBAUTHN_DEMO_ORIGIN=https://sample.ngrok-free.app
            """.trimIndent(),
        )
        val parserCwd = rootDir.resolve("samples/passkey-cli").createDirectories()
        val parser = CliParser(cwd = parserCwd)

        val invocation = parser.parse(
            arrayOf(
                "register",
                "--user-name",
                "alice",
                "--endpoint",
                "https://login.example.com:8443/base",
            ),
        )

        assertTrue(invocation is CliInvocation.Register)
        assertEquals("https://login.example.com:8443/base", invocation.common.endpointBase)
        assertEquals("login.example.com", invocation.common.rpId)
        assertEquals("https://login.example.com:8443", invocation.common.origin)
    }
}
