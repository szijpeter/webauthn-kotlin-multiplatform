package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.mutableStateListOf
import co.touchlab.kermit.Logger
import dev.webauthn.samples.composepasskey.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock

internal class DebugLogStore(
    private val logger: Logger = Logger.withTag("PasskeyDemo"),
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) {
    private val entriesState = mutableStateListOf<DebugLogEntry>()
    private var nextId: Long = 1L

    val entries: List<DebugLogEntry>
        get() = entriesState

    fun d(source: String, message: String) {
        append(DebugLogLevel.DEBUG, source, message, throwable = null)
    }

    fun i(source: String, message: String) {
        append(DebugLogLevel.INFO, source, message, throwable = null)
    }

    fun w(source: String, message: String) {
        append(DebugLogLevel.WARN, source, message, throwable = null)
    }

    fun e(source: String, message: String, throwable: Throwable? = null) {
        append(DebugLogLevel.ERROR, source, message, throwable = throwable)
    }

    private fun append(
        level: DebugLogLevel,
        source: String,
        message: String,
        throwable: Throwable?,
    ) {
        val entry = DebugLogEntry(
            id = nextId,
            timestamp = Clock.System.now(),
            level = level,
            source = source,
            message = message,
        )
        nextId += 1
        entriesState.add(index = 0, element = entry)
        while (entriesState.size > maxEntries) {
            entriesState.removeAt(entriesState.lastIndex)
        }

        val line = "${entry.formatTimestampForDisplay()} [${level.name}] ${entry.source}: ${entry.message}"
        when (level) {
            DebugLogLevel.DEBUG -> logger.d { line }
            DebugLogLevel.INFO -> logger.i { line }
            DebugLogLevel.WARN -> logger.w { line }
            DebugLogLevel.ERROR -> logger.e(throwable) { line }
        }
    }
}

internal fun DebugLogEntry.formatTimestampForDisplay(): String {
    val local = timestamp.toLocalDateTime(TimeZone.currentSystemDefault())
    val millis = local.nanosecond / NANOS_PER_MILLI
    return "${local.hour.twoDigits()}:${local.minute.twoDigits()}:${local.second.twoDigits()}.${millis.threeDigits()}"
}

private fun Int.twoDigits(): String = toString().padStart(TWO_DIGIT_WIDTH, '0')

private fun Int.threeDigits(): String = toString().padStart(THREE_DIGIT_WIDTH, '0')

private const val DEFAULT_MAX_ENTRIES: Int = 200
private const val NANOS_PER_MILLI: Int = 1_000_000
private const val TWO_DIGIT_WIDTH: Int = 2
private const val THREE_DIGIT_WIDTH: Int = 3
