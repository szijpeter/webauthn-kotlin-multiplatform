package dev.webauthn.samples.composepasskey.model

import kotlin.time.Instant

public enum class StatusTone {
    IDLE,
    WORKING,
    SUCCESS,
    WARNING,
    ERROR,
}

public enum class DebugLogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
}

public data class DebugLogEntry(
    public val id: Long,
    public val timestamp: Instant,
    public val level: DebugLogLevel,
    public val source: String,
    public val message: String,
)

public data class PasskeyDemoStatus(
    val tone: StatusTone,
    val headline: String,
    val detail: String? = null,
)
