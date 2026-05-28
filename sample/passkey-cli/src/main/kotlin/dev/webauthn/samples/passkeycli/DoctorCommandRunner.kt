package dev.webauthn.samples.passkeycli

import java.awt.Desktop
import java.net.URI
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile

internal class DoctorCommandRunner(
    private val commandExecutor: CommandExecutor,
    private val stdout: Appendable = System.out,
    private val stderr: Appendable = System.err,
) {
    suspend fun run(command: CliInvocation.Doctor): Int {
        return when (command.common.authenticatorMode) {
            AuthenticatorMode.BROWSER -> runBrowserDoctor(command)
            AuthenticatorMode.CTAP -> runCtapDoctor(command)
        }
    }

    private suspend fun runBrowserDoctor(command: CliInvocation.Doctor): Int {
        var failedChecks = 0
        if (!checkDesktopBrowserSupport()) failedChecks += 1
        if (!checkOriginEndpointConsistency(command.common.endpointBase, command.common.origin)) failedChecks += 1

        return if (failedChecks == 0) {
            stdout.appendLine("Doctor result: PASS")
            0
        } else {
            stderr.appendLine("Doctor result: FAIL ($failedChecks blocking check(s) failed).")
            1
        }
    }

    private suspend fun runCtapDoctor(command: CliInvocation.Doctor): Int {
        var failedChecks = 0
        if (!checkOs()) failedChecks += 1
        if (!checkBridgeScript(command.common.pythonBridgePath)) failedChecks += 1
        if (!checkPython(command.common.pythonBinary)) failedChecks += 1
        if (!checkPythonFido2(command.common.pythonBinary)) failedChecks += 1
        probeDevices(command.common.pythonBinary)

        return if (failedChecks == 0) {
            stdout.appendLine("Doctor result: PASS")
            0
        } else {
            stderr.appendLine("Doctor result: FAIL ($failedChecks blocking check(s) failed).")
            1
        }
    }

    private fun checkDesktopBrowserSupport(): Boolean {
        if (!Desktop.isDesktopSupported()) {
            stderr.appendLine("Browser check failed: Java Desktop API is unavailable on this runtime.")
            return false
        }
        if (!Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            stderr.appendLine("Browser check failed: Desktop browse action is unsupported.")
            return false
        }
        stdout.appendLine("Browser check: Desktop browse action is supported.")
        return true
    }

    private fun checkOriginEndpointConsistency(endpointBase: String, origin: String): Boolean {
        val endpointOrigin = endpointOrigin(endpointBase)
        if (endpointOrigin == null) {
            stderr.appendLine("Endpoint/origin check failed: endpoint '$endpointBase' is not a valid URI.")
            return false
        }
        if (origin != endpointOrigin) {
            stderr.appendLine(
                "Endpoint/origin check failed: origin '$origin' does not match endpoint origin '$endpointOrigin'. " +
                    "Browser mode requires matching origin.",
            )
            return false
        }
        stdout.appendLine("Endpoint/origin check: origin matches endpoint ($endpointOrigin).")
        return true
    }

    private fun endpointOrigin(endpointBase: String): String? {
        return runCatching {
            val endpoint = URI(endpointBase)
            val scheme = endpoint.scheme
            val host = endpoint.host
            if (scheme.isNullOrBlank() || host.isNullOrBlank()) {
                return@runCatching null
            }
            val port = endpoint.port
            if (port == -1) {
                "$scheme://$host"
            } else {
                "$scheme://$host:$port"
            }
        }.getOrNull()
    }

    private fun checkOs(): Boolean {
        val osName = System.getProperty("os.name")
        val isMacOs = osName.contains("Mac", ignoreCase = true)
        if (isMacOs) {
            stdout.appendLine("OS check: macOS detected ($osName)")
            return true
        }
        stderr.appendLine("OS check failed: native CLI POC is macOS-only, detected '$osName'.")
        return false
    }

    private fun checkBridgeScript(bridgePathString: String): Boolean {
        val bridgePath = Path.of(bridgePathString)
        if (bridgePath.exists() && bridgePath.isRegularFile()) {
            stdout.appendLine("Bridge script check: found ${bridgePath.toAbsolutePath()}")
            return true
        }
        stderr.appendLine("Bridge script check failed: '${bridgePath.toAbsolutePath()}' does not exist.")
        return false
    }

    private suspend fun checkPython(pythonBinary: String): Boolean {
        val pythonVersion = runCatching {
            commandExecutor.execute(
                command = listOf(pythonBinary, "--version"),
            )
        }.getOrElse { error ->
            stderr.appendLine(
                "Python check failed: unable to execute '$pythonBinary --version'. " +
                    "${error.message ?: error::class.simpleName}",
            )
            return false
        }
        if (pythonVersion.exitCode == 0) {
            val resolvedVersion = pythonVersion.stdout.ifBlank { pythonVersion.stderr }
            stdout.appendLine("Python check: $resolvedVersion")
            return true
        }
        stderr.appendLine(
            "Python check failed: unable to execute '$pythonBinary --version'. " +
                pythonVersion.stderr,
        )
        return false
    }

    private suspend fun checkPythonFido2(pythonBinary: String): Boolean {
        val fido2Import = runCatching {
            commandExecutor.execute(
                command = listOf(
                    pythonBinary,
                    "-c",
                    "import fido2; print('python-fido2 import ok')",
                ),
            )
        }.getOrElse { error ->
            stderr.appendLine(
                "Dependency check failed: python-fido2 import invocation failed. " +
                    "${error.message ?: error::class.simpleName}",
            )
            return false
        }
        if (fido2Import.exitCode == 0) {
            stdout.appendLine("Dependency check: ${fido2Import.stdout}")
            return true
        }
        stderr.appendLine("Dependency check failed: python-fido2 is unavailable. ${fido2Import.stderr}")
        return false
    }

    private suspend fun probeDevices(pythonBinary: String) {
        val deviceProbe = runCatching {
            commandExecutor.execute(
                command = listOf(
                    pythonBinary,
                    "-c",
                    "from fido2.hid import CtapHidDevice; print(len(list(CtapHidDevice.list_devices())))",
                ),
            )
        }.getOrElse { error ->
            stderr.appendLine(
                "Device probe warning: unable to probe CTAP devices via '$pythonBinary'. " +
                    "${error.message ?: error::class.simpleName}",
            )
            return
        }
        if (deviceProbe.exitCode == 0) {
            val discovered = deviceProbe.stdout.toIntOrNull()
            when {
                discovered == null -> {
                    stderr.appendLine(
                        "Device probe warning: unexpected output '${deviceProbe.stdout}'.",
                    )
                }
                discovered == 0 -> stderr.appendLine(
                    "Device probe warning: no CTAP HID device detected. " +
                        "Use --authenticator browser for platform passkeys.",
                )
                else -> stdout.appendLine("Device probe: detected $discovered CTAP HID device(s).")
            }
            return
        }
        val probeError = deviceProbe.stderr.ifBlank { deviceProbe.stdout }
        stderr.appendLine("Device probe warning: $probeError")
    }
}
