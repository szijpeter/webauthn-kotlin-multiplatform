package dev.webauthn.samples.passkeycli

import kotlinx.coroutines.test.runTest
import kotlin.io.path.createTempFile
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DoctorCommandRunnerTest {
    @Test
    fun run_whenPythonLaunchThrows_reportsFailuresInsteadOfThrowing() = runTest {
        val bridgeScript = createTempFile(prefix = "fido2-bridge", suffix = ".py")
        bridgeScript.writeText("#!/usr/bin/env python3\n")
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val runner = DoctorCommandRunner(
            commandExecutor = ThrowingCommandExecutor(),
            stdout = stdout,
            stderr = stderr,
        )

        val exitCode = runner.run(
            CliInvocation.Doctor(
                common = CommonCliOptions(
                    endpointBase = "http://127.0.0.1:8080",
                    rpId = "localhost",
                    origin = "https://localhost",
                    pythonBinary = "/missing/python3",
                    pythonBridgePath = bridgeScript.toString(),
                ),
            ),
        )

        assertEquals(1, exitCode)
        assertTrue(stderr.toString().contains("Python check failed"))
        assertTrue(stderr.toString().contains("Dependency check failed"))
        assertTrue(stderr.toString().contains("Device probe warning"))
    }
}

private class ThrowingCommandExecutor : CommandExecutor {
    override suspend fun execute(command: List<String>, stdin: String?): CommandExecutionResult {
        throw IllegalStateException("simulated launch failure")
    }
}
