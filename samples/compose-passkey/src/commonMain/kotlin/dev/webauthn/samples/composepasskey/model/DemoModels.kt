package dev.webauthn.samples.composepasskey.model

public enum class StatusTone {
    IDLE,
    WORKING,
    SUCCESS,
    WARNING,
    ERROR,
}

public data class PasskeyDemoLogEntry(
    public val id: Long,
    public val timestamp: String,
    public val tone: StatusTone,
    public val message: String,
)

public data class PasskeyDemoStatus(
    val tone: StatusTone,
    val headline: String,
    val detail: String? = null,
)
