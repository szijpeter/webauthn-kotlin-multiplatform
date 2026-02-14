package dev.webauthn.model

@RequiresOptIn(
    message = "This API depends on WebAuthn Level 3 features that may evolve before broader stabilization.",
    level = RequiresOptIn.Level.WARNING,
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
)
public annotation class ExperimentalWebAuthnL3Api
