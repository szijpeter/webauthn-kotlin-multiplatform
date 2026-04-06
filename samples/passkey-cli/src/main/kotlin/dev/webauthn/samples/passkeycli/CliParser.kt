package dev.webauthn.samples.passkeycli

import dev.webauthn.model.Base64UrlBytes
import java.net.URI
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.readLines

internal data class CommonCliOptions(
    val endpointBase: String,
    val rpId: String,
    val origin: String,
    val authenticatorMode: AuthenticatorMode,
    val pythonBinary: String,
    val pythonBridgePath: String,
)

internal enum class AuthenticatorMode(
    val cliValue: String,
) {
    BROWSER("browser"),
    CTAP("ctap"),
    ;

    companion object {
        fun parse(value: String): AuthenticatorMode {
            return entries.firstOrNull { it.cliValue == value.lowercase() }
                ?: throw CliUsageException(
                    "Unsupported authenticator mode '$value'. Supported values: browser, ctap.",
                )
        }
    }
}

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
    private val localPropertiesDefaults: LocalPropertiesDefaults by lazy { resolveLocalPropertiesDefaults(cwd) }

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
        val endpointBase = options["--endpoint"] ?: localPropertiesDefaults.endpointBase ?: DEFAULT_ENDPOINT
        val endpointExplicit = "--endpoint" in options
        return CommonCliOptions(
            endpointBase = endpointBase,
            rpId = when {
                "--rp-id" in options -> options.getValue("--rp-id")
                endpointExplicit -> defaultRpIdForEndpoint(endpointBase)
                else -> localPropertiesDefaults.rpId ?: defaultRpIdForEndpoint(endpointBase)
            },
            origin = when {
                "--origin" in options -> options.getValue("--origin")
                endpointExplicit -> defaultOriginForEndpoint(endpointBase)
                else -> localPropertiesDefaults.origin ?: defaultOriginForEndpoint(endpointBase)
            },
            authenticatorMode = options["--authenticator"]?.let(AuthenticatorMode::parse) ?: AuthenticatorMode.BROWSER,
            pythonBinary = options["--python-bin"] ?: resolveDefaultPythonBinary(),
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
        return findUpwards(
            cwd,
            "samples/passkey-cli/scripts/fido2_bridge.py",
            "scripts/fido2_bridge.py",
        )?.toString()
            ?: cwd.resolve("samples/passkey-cli/scripts/fido2_bridge.py").normalize().toString()
    }

    private fun resolveDefaultPythonBinary(): String {
        return findUpwards(
            cwd,
            "samples/passkey-cli/.venv/bin/python",
            ".venv/bin/python",
        )?.toString() ?: "python3"
    }

    companion object {
        val HELP_KEYS: Set<String> = setOf("-h", "--help")
        val COMMON_KEYS: Set<String> = setOf(
            "--endpoint",
            "--rp-id",
            "--origin",
            "--authenticator",
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
                  --endpoint <url>            Backend base URL (default: local.properties WEBAUTHN_DEMO_ENDPOINT, else http://localhost:8080)
                  --rp-id <rpId>              Relying party ID (default: local.properties WEBAUTHN_DEMO_RP_ID, else endpoint host)
                  --origin <origin>           WebAuthn origin (default: local.properties WEBAUTHN_DEMO_ORIGIN, else endpoint origin)
                  --authenticator <mode>      browser (default) or ctap
                  --python-bin <path>         Python executable (ctap mode; default: auto .venv/bin/python, else python3)
                  --python-bridge <path>      Path to fido2 bridge script (ctap mode)
                
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

private const val DEFAULT_ENDPOINT: String = "http://localhost:8080"
private const val DEFAULT_RP_ID: String = "localhost"
private const val DEFAULT_ORIGIN: String = "http://localhost:8080"

private data class LocalPropertiesDefaults(
    val endpointBase: String? = null,
    val rpId: String? = null,
    val origin: String? = null,
)

private fun defaultRpIdForEndpoint(endpointBase: String): String {
    return runCatching {
        val host = URI(endpointBase).host
        if (host.isNullOrBlank()) {
            DEFAULT_RP_ID
        } else {
            host
        }
    }.getOrDefault(DEFAULT_RP_ID)
}

private fun defaultOriginForEndpoint(endpointBase: String): String {
    return runCatching {
        val endpointUri = URI(endpointBase)
        val scheme = endpointUri.scheme ?: return@runCatching DEFAULT_ORIGIN
        val host = endpointUri.host ?: return@runCatching DEFAULT_ORIGIN
        val port = endpointUri.port
        if (port == -1) {
            "$scheme://$host"
        } else {
            "$scheme://$host:$port"
        }
    }.getOrDefault(DEFAULT_ORIGIN)
}

private fun findUpwards(start: Path, vararg candidates: String): Path? {
    var cursor: Path? = start
    while (cursor != null) {
        for (candidate in candidates) {
            val candidatePath = cursor.resolve(candidate)
            if (candidatePath.exists() && candidatePath.isRegularFile()) {
                return candidatePath
            }
        }
        cursor = cursor.parent
    }
    return null
}

private fun resolveLocalPropertiesDefaults(cwd: Path): LocalPropertiesDefaults {
    val localPropertiesPath = findUpwards(cwd, "local.properties") ?: return LocalPropertiesDefaults()
    val values = runCatching {
        localPropertiesPath.readLines()
            .mapNotNull(::parsePropertyLine)
            .toMap()
    }.getOrElse { emptyMap() }
    return LocalPropertiesDefaults(
        endpointBase = values["WEBAUTHN_DEMO_ENDPOINT"]?.takeIf(String::isNotBlank),
        rpId = values["WEBAUTHN_DEMO_RP_ID"]?.takeIf(String::isNotBlank),
        origin = values["WEBAUTHN_DEMO_ORIGIN"]?.takeIf(String::isNotBlank),
    )
}

private fun parsePropertyLine(line: String): Pair<String, String>? {
    val trimmed = line.trim()
    if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        return null
    }
    val separatorIndex = trimmed.indexOf('=')
    if (separatorIndex <= 0) {
        return null
    }
    val key = trimmed.substring(0, separatorIndex).trim()
    val value = trimmed.substring(separatorIndex + 1).trim()
    return key to value
}
