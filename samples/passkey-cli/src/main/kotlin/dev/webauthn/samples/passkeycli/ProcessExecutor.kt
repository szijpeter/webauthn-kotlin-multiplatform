package dev.webauthn.samples.passkeycli

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.concurrent.thread

internal data class CommandExecutionResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
)

internal interface CommandExecutor {
    suspend fun execute(command: List<String>, stdin: String? = null): CommandExecutionResult
}

internal class DefaultCommandExecutor : CommandExecutor {
    override suspend fun execute(command: List<String>, stdin: String?): CommandExecutionResult =
        withContext(Dispatchers.IO) {
            val process = ProcessBuilder(command).start()
            val stdoutBuffer = StringBuilder()
            val stderrBuffer = StringBuilder()

            val stdoutReader = thread(name = "passkey-cli-stdout-reader") {
                process.inputStream.bufferedReader().use { reader ->
                    reader.forEachLine { line ->
                        stdoutBuffer.appendLine(line)
                    }
                }
            }

            val stderrReader = thread(name = "passkey-cli-stderr-reader") {
                process.errorStream.bufferedReader().use { reader ->
                    reader.forEachLine { line ->
                        stderrBuffer.appendLine(line)
                    }
                }
            }

            if (stdin != null) {
                process.outputStream.bufferedWriter().use { writer ->
                    writer.write(stdin)
                }
            } else {
                process.outputStream.close()
            }

            val exitCode = process.waitFor()
            stdoutReader.join()
            stderrReader.join()

            CommandExecutionResult(
                exitCode = exitCode,
                stdout = stdoutBuffer.toString().trim(),
                stderr = stderrBuffer.toString().trim(),
            )
        }
}
