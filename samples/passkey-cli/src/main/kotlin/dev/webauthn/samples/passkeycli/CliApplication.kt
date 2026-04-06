package dev.webauthn.samples.passkeycli

import dev.webauthn.network.KtorPasskeyServerClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json

internal class CliApplication(
    private val parser: CliParser = CliParser(),
    private val commandExecutor: CommandExecutor = DefaultCommandExecutor(),
    private val stdout: Appendable = System.out,
    private val stderr: Appendable = System.err,
) {
    suspend fun run(args: Array<String>): Int {
        val invocation = try {
            parser.parse(args)
        } catch (error: CliUsageException) {
            stderr.appendLine(error.message)
            stderr.appendLine(CliParser.usage())
            return EXIT_PARSE_USAGE
        }

        return when (invocation) {
            CliInvocation.Help -> {
                stdout.appendLine(CliParser.usage())
                0
            }
            is CliInvocation.Doctor -> DoctorCommandRunner(
                commandExecutor = commandExecutor,
                stdout = stdout,
                stderr = stderr,
            ).run(invocation)
            is CliInvocation.Register -> runCeremony(invocation)
            is CliInvocation.Authenticate -> runCeremony(invocation)
        }
    }

    private suspend fun runCeremony(invocation: CliInvocation.Ceremony): Int {
        val httpClient = createHttpClient()
        return try {
            val serverClient = KtorPasskeyServerClient(
                httpClient = httpClient,
                endpointBase = invocation.common.endpointBase,
            )
            val adapter = when (invocation.common.authenticatorMode) {
                AuthenticatorMode.BROWSER -> BrowserHandoffAdapter(
                    endpointBase = invocation.common.endpointBase,
                    stdout = stdout,
                )
                AuthenticatorMode.CTAP -> PythonFido2Adapter(
                    commandExecutor = commandExecutor,
                    pythonBinary = invocation.common.pythonBinary,
                    bridgeScriptPath = invocation.common.pythonBridgePath,
                )
            }
            val runner = PasskeyCeremonyRunner(
                authenticatorAdapter = adapter,
                serverClient = serverClient,
                stdout = stdout,
                stderr = stderr,
            )
            when (invocation) {
                is CliInvocation.Register -> runner.runRegister(invocation)
                is CliInvocation.Authenticate -> runner.runAuthenticate(invocation)
            }
        } finally {
            httpClient.close()
        }
    }

    private fun createHttpClient(): HttpClient {
        return HttpClient(CIO) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                    },
                )
            }
        }
    }
}

internal const val EXIT_PARSE_USAGE: Int = 64
