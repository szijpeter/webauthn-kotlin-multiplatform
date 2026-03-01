package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyCapabilities
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PasskeyDemoControllerTest {
    @Test
    fun health_check_success_updates_status_and_logs() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                healthResult = PasskeyDemoActionResult.Success("Temp server is healthy (200)."),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.CheckHealth)

        val state = controller.state.value
        assertEquals(StatusTone.SUCCESS, state.statusTone)
        assertTrue(state.statusHeadline.contains("healthy"))
        assertTrue(state.logs.first().message.contains("healthy"))
    }

    @Test
    fun register_success_updates_status_and_logs() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                registerResult = PasskeyDemoActionResult.Success("Registration complete for demo@local."),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.Register)

        val state = controller.state.value
        assertEquals(StatusTone.SUCCESS, state.statusTone)
        assertTrue(state.statusHeadline.contains("Registration complete"))
        assertTrue(state.logs.first().message.contains("Registration complete"))
    }

    @Test
    fun register_validation_invalid_shows_field_errors() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                registerResult = PasskeyDemoActionResult.Failure(
                    category = PasskeyDemoErrorCategory.VALIDATION,
                    message = "startRegistration validation failed: challenge: missing",
                ),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.Register)

        val state = controller.state.value
        assertEquals(StatusTone.ERROR, state.statusTone)
        assertEquals("Validation", state.statusHeadline)
        assertTrue(state.statusDetail.orEmpty().contains("[Validation]"))
        assertTrue(state.statusDetail.orEmpty().contains("challenge"))
    }

    @Test
    fun register_platform_failure_surfaces_error_category() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                registerResult = PasskeyDemoActionResult.Failure(
                    category = PasskeyDemoErrorCategory.PLATFORM,
                    message = "Registration failed: Provider unavailable",
                ),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.Register)

        val state = controller.state.value
        assertEquals(StatusTone.ERROR, state.statusTone)
        assertEquals("Platform", state.statusHeadline)
        assertTrue(state.statusDetail.orEmpty().contains("[Platform]"))
    }

    @Test
    fun authenticate_success_updates_status_and_logs() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                authenticateResult = PasskeyDemoActionResult.Success("Sign-in complete for demo-user-1."),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.SignIn)

        val state = controller.state.value
        assertEquals(StatusTone.SUCCESS, state.statusTone)
        assertTrue(state.statusHeadline.contains("Sign-in complete"))
        assertTrue(state.logs.first().message.contains("Sign-in complete"))
    }

    @Test
    fun authenticate_before_register_handles_no_credential_gracefully() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                authenticateResult = PasskeyDemoActionResult.Failure(
                    category = PasskeyDemoErrorCategory.PLATFORM,
                    message = "Authentication failed: No credentials found",
                ),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.SignIn)

        val state = controller.state.value
        assertEquals(StatusTone.ERROR, state.statusTone)
        assertEquals("Platform", state.statusHeadline)
        assertTrue(state.statusDetail.orEmpty().contains("No credentials found"))
        assertTrue(state.logs.first().message.contains("No credentials found"))
    }

    @Test
    fun capabilities_load_success_and_failure_fallback() = runTest {
        val successController = PasskeyDemoController(
            gateway = FakeGateway(
                capabilities = PasskeyCapabilities(supportsPrf = true, supportsSecurityKey = true),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )
        successController.bootstrap()
        assertTrue(successController.state.value.capabilities.supportsPrf)
        assertTrue(successController.state.value.capabilities.supportsSecurityKey)

        val fallbackController = PasskeyDemoController(
            gateway = FakeGateway(capabilitiesError = IllegalStateException("Unavailable")),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )
        fallbackController.bootstrap()

        assertEquals(PasskeyCapabilities(), fallbackController.state.value.capabilities)
        assertTrue(fallbackController.state.value.logs.first().message.contains("Capabilities loaded"))
        assertTrue(fallbackController.state.value.logs.any { it.message.contains("safe defaults") })
    }

    @Test
    fun transport_exception_does_not_crash_controller() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(registerThrowable = IllegalStateException("network timeout")),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.Register)

        val state = controller.state.value
        assertEquals(StatusTone.ERROR, state.statusTone)
        assertEquals("Transport", state.statusHeadline)
        assertTrue(state.statusDetail.orEmpty().contains("network timeout"))
    }

    @Test
    fun platform_failure_surfaces_actionable_hint() = runTest {
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                registerResult = PasskeyDemoActionResult.Failure(
                    category = PasskeyDemoErrorCategory.PLATFORM,
                    message = "Registration failed: createCredentialAsync no provider dependencies found",
                ),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.Register)

        val state = controller.state.value
        assertEquals("Platform", state.statusHeadline)
        assertTrue(state.statusDetail.orEmpty().contains("no provider dependencies found"))
        assertTrue(state.statusDetail.orEmpty().contains("credentials-play-services-auth"))
    }

    @Test
    fun long_error_uses_compact_headline_and_keeps_detail() = runTest {
        val longMessage = buildString {
            append("Registration failed: createCredentialAsync no provider dependencies found. ")
            append("Please ensure provider dependencies are added and runtime is configured.")
        }
        val controller = PasskeyDemoController(
            gateway = FakeGateway(
                registerResult = PasskeyDemoActionResult.Failure(
                    category = PasskeyDemoErrorCategory.PLATFORM,
                    message = longMessage,
                ),
            ),
            timestampProvider = { "2026-03-01T10:00:00Z" },
        )

        controller.dispatch(PasskeyDemoIntent.Register)

        val state = controller.state.value
        assertEquals("Platform", state.statusHeadline)
        assertTrue(state.statusDetail.orEmpty().contains("Registration failed"))
        assertTrue(state.statusDetail.orEmpty().contains("credentials-play-services-auth"))
    }
}

private class FakeGateway(
    private val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    private val capabilitiesError: Throwable? = null,
    private val registerThrowable: Throwable? = null,
    private val healthResult: PasskeyDemoActionResult = PasskeyDemoActionResult.Success("Temp server is healthy (200)."),
    private val registerResult: PasskeyDemoActionResult = PasskeyDemoActionResult.Success("Registration complete for demo@local."),
    private val authenticateResult: PasskeyDemoActionResult = PasskeyDemoActionResult.Success("Sign-in complete for demo-user-1."),
) : PasskeyDemoGateway {
    override suspend fun checkHealth(config: PasskeyDemoConfig): PasskeyDemoActionResult = healthResult

    override suspend fun register(config: PasskeyDemoConfig): PasskeyDemoActionResult {
        if (registerThrowable != null) {
            throw registerThrowable
        }
        return registerResult
    }

    override suspend fun authenticate(config: PasskeyDemoConfig): PasskeyDemoActionResult = authenticateResult

    override suspend fun capabilities(): PasskeyCapabilities {
        if (capabilitiesError != null) {
            throw capabilitiesError
        }
        return capabilities
    }
}
