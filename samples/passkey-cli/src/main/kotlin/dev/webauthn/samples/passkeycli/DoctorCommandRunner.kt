package dev.webauthn.samples.passkeycli

import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile

internal class DoctorCommandRunner(
    private val commandExecutor: CommandExecutor,
    private val stdout: Appendable = System.out,
    private val stderr: Appendable = System.err,
) {
    suspend fun run(command: CliInvocation.Doctor): Int {
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
        val pythonVersion = commandExecutor.execute(
            command = listOf(pythonBinary, "--version"),
        )
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
        val fido2Import = commandExecutor.execute(
            command = listOf(
                pythonBinary,
                "-c",
                "import fido2; print('python-fido2 import ok')",
            ),
        )
        if (fido2Import.exitCode == 0) {
            stdout.appendLine("Dependency check: ${fido2Import.stdout}")
            return true
        }
        stderr.appendLine("Dependency check failed: python-fido2 is unavailable. ${fido2Import.stderr}")
        return false
    }

    private suspend fun probeDevices(pythonBinary: String) {
        val deviceProbe = commandExecutor.execute(
            command = listOf(
                pythonBinary,
                "-c",
                "from fido2.hid import CtapHidDevice; print(len(list(CtapHidDevice.list_devices())))",
            ),
        )
        if (deviceProbe.exitCode == 0) {
            val discovered = deviceProbe.stdout.toIntOrNull()
            when {
                discovered == null -> {
                    stderr.appendLine(
                        "Device probe warning: unexpected output '${deviceProbe.stdout}'.",
                    )
                }
                discovered == 0 -> stderr.appendLine("Device probe warning: no CTAP HID device detected.")
                else -> stdout.appendLine("Device probe: detected $discovered CTAP HID device(s).")
            }
            return
        }
        val probeError = deviceProbe.stderr.ifBlank { deviceProbe.stdout }
        stderr.appendLine("Device probe warning: $probeError")
    }
}
