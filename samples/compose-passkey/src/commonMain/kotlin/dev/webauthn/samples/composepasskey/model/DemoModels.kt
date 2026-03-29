package dev.webauthn.samples.composepasskey.model

import kotlin.time.Instant

enum class StatusTone {
    IDLE,
    WORKING,
    SUCCESS,
    WARNING,
    ERROR,
}

enum class DebugLogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
}

data class DebugLogEntry(
    val id: Long,
    val timestamp: Instant,
    val level: DebugLogLevel,
    val source: String,
    val message: String,
)

data class PasskeyDemoStatus(
    val tone: StatusTone,
    val headline: String,
    val detail: String? = null,
)
