package dev.webauthn.samples.passkeycli

import dev.webauthn.model.Base64UrlBytes
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile

internal data class CommonCliOptions(
    val endpointBase: String,
    val rpId: String,
    val origin: String,
    val pythonBinary: String,
    val pythonBridgePath: String,
)

internal sealed interface CliInvocation {
    data object Help : CliInvocation

    sealed interface Ceremony : CliInvocation {
        val common: CommonCliOptions
    }

    data class Doctor(
        val common: CommonCliOptions,
    ) : CliInvocation

    data class Register(
        override val common: CommonCliOptions,
        val userName: String,
        val userDisplayName: String,
        val userHandle: String,
    ) : Ceremony

    data class Authenticate(
        override val common: CommonCliOptions,
        val userName: String,
        val userHandle: String?,
    ) : Ceremony
}

internal class CliUsageException(message: String) : IllegalArgumentException(message)

internal class CliParser(
    private val cwd: Path = Path.of("").toAbsolutePath(),
) {
    fun parse(args: Array<String>): CliInvocation {
        if (args.isEmpty()) {
            return CliInvocation.Help
        }

        val command = args.first().lowercase()
        if (command == "help" || command == "-h" || command == "--help") {
            return CliInvocation.Help
        }

        val options = parseOptions(args.drop(1))
        if ("--help" in options) {
            return CliInvocation.Help
        }

        return when (command) {
            "doctor" -> parseDoctor(options)
            "register" -> parseRegister(options)
            "authenticate" -> parseAuthenticate(options)
            else -> throw CliUsageException("Unknown command '$command'.")
        }
    }

    private fun parseDoctor(options: Map<String, String>): CliInvocation.Doctor {
        validateAllowed(
            options = options,
            allowed = COMMON_KEYS + HELP_KEYS,
        )
        return CliInvocation.Doctor(commonOptions(options))
    }

    private fun parseRegister(options: Map<String, String>): CliInvocation.Register {
        validateAllowed(
            options = options,
            allowed = COMMON_KEYS + HELP_KEYS + REGISTER_KEYS,
        )
        val common = commonOptions(options)
        val userName = requireOption(options, "--user-name")
        val userDisplayName = options["--user-display-name"] ?: userName
        val userHandle = options["--user-handle"] ?: generatedUserHandle(userName)
        return CliInvocation.Register(
            common = common,
            userName = userName,
            userDisplayName = userDisplayName,
            userHandle = userHandle,
        )
    }

    private fun parseAuthenticate(options: Map<String, String>): CliInvocation.Authenticate {
        validateAllowed(
            options = options,
            allowed = COMMON_KEYS + HELP_KEYS + AUTHENTICATE_KEYS,
        )
        val common = commonOptions(options)
        val userName = requireOption(options, "--user-name")
        return CliInvocation.Authenticate(
            common = common,
            userName = userName,
            userHandle = options["--user-handle"],
        )
    }

    private fun commonOptions(options: Map<String, String>): CommonCliOptions {
        return CommonCliOptions(
            endpointBase = options["--endpoint"] ?: "http://127.0.0.1:8080",
            rpId = options["--rp-id"] ?: "localhost",
            origin = options["--origin"] ?: "https://localhost",
            pythonBinary = options["--python-bin"] ?: "python3",
            pythonBridgePath = options["--python-bridge"] ?: resolveDefaultBridgePath(),
        )
    }

    private fun parseOptions(args: List<String>): Map<String, String> {
        val values = linkedMapOf<String, String>()
        var index = 0
        while (index < args.size) {
            val token = args[index]
            if (token in HELP_KEYS) {
                values["--help"] = "true"
                index += 1
                continue
            }
            if (!token.startsWith("--")) {
                throw CliUsageException("Unexpected argument '$token'. Options must use --key value format.")
            }
            if (index + 1 >= args.size) {
                throw CliUsageException("Missing value for option '$token'.")
            }
            val value = args[index + 1]
            values[token] = value
            index += 2
        }
        return values
    }

    private fun requireOption(options: Map<String, String>, key: String): String {
        return options[key]?.takeIf(String::isNotBlank)
            ?: throw CliUsageException("Missing required option '$key'.")
    }

    private fun validateAllowed(options: Map<String, String>, allowed: Set<String>) {
        val unknown = options.keys.filterNot { it in allowed }
        if (unknown.isNotEmpty()) {
            throw CliUsageException("Unknown option(s): ${unknown.joinToString(", ")}")
        }
    }

    private fun generatedUserHandle(userName: String): String {
        return Base64UrlBytes.fromBytes(userName.encodeToByteArray()).encoded()
    }

    private fun resolveDefaultBridgePath(): String {
        var cursor: Path? = cwd
        while (cursor != null) {
            val repoRelative = cursor.resolve("samples/passkey-cli/scripts/fido2_bridge.py")
            if (repoRelative.exists() && repoRelative.isRegularFile()) {
                return repoRelative.toString()
            }
            val moduleRelative = cursor.resolve("scripts/fido2_bridge.py")
            if (moduleRelative.exists() && moduleRelative.isRegularFile()) {
                return moduleRelative.toString()
            }
            cursor = cursor.parent
        }
        return cwd.resolve("samples/passkey-cli/scripts/fido2_bridge.py").normalize().toString()
    }

    companion object {
        val HELP_KEYS: Set<String> = setOf("-h", "--help")
        val COMMON_KEYS: Set<String> = setOf(
            "--endpoint",
            "--rp-id",
            "--origin",
            "--python-bin",
            "--python-bridge",
        )
        val REGISTER_KEYS: Set<String> = setOf(
            "--user-name",
            "--user-display-name",
            "--user-handle",
        )
        val AUTHENTICATE_KEYS: Set<String> = setOf(
            "--user-name",
            "--user-handle",
        )

        fun usage(): String {
            return """
                Usage:
                  passkey-cli doctor [common options]
                  passkey-cli register --user-name <name> [register options] [common options]
                  passkey-cli authenticate --user-name <name> [authenticate options] [common options]
                
                Common options:
                  --endpoint <url>            Backend base URL (default: http://127.0.0.1:8080)
                  --rp-id <rpId>              Relying party ID (default: localhost)
                  --origin <origin>           WebAuthn origin (default: https://localhost)
                  --python-bin <path>         Python executable (default: python3)
                  --python-bridge <path>      Path to fido2 bridge script
                
                Register options:
                  --user-name <name>          Required account username
                  --user-display-name <name>  Optional display name (default: user-name)
                  --user-handle <b64url>      Optional user handle (default: base64url(user-name))
                
                Authenticate options:
                  --user-name <name>          Required account username
                  --user-handle <b64url>      Optional user handle
            """.trimIndent()
        }
    }
}
