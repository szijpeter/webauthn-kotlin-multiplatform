package dev.webauthn.samples.passkeycli

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CliApplicationTest {
    @Test
    fun run_unknownCommand_returnsParseUsageExitCode() = runTest {
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val app = CliApplication(
            stdout = stdout,
            stderr = stderr,
        )

        val exitCode = app.run(arrayOf("unknown-cmd"))

        assertEquals(EXIT_PARSE_USAGE, exitCode)
        assertTrue(stderr.toString().contains("Unknown command"))
        assertTrue(stderr.toString().contains("Usage:"))
    }
}
