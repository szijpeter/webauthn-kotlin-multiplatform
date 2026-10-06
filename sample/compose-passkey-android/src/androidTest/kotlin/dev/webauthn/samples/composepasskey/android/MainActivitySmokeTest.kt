package dev.webauthn.samples.composepasskey.android

import android.content.Intent
import android.graphics.Bitmap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import java.io.File
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivitySmokeTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val testName = TestName()

    @Test
    fun liveAppExposesAuthenticationAndDismissibleLogs() {
        withScenario(ActivityScenario.launch(MainActivity::class.java)) {
            compose.onNodeWithText("Register").assertIsDisplayed().assertIsEnabled()
            compose.onNodeWithText("Sign In").assertIsEnabled()
            compose.onNodeWithContentDescription("Debug logs").performClick()
            compose.onNodeWithText("Done").assertIsDisplayed().performClick()
            compose.onNodeWithText("Register").assertIsDisplayed()
        }
    }

    @Test
    fun busyCeremonyDisablesBothActionsButKeepsDiagnosticsAvailable() {
        withScenario(gallery("busy")) {
            compose.onNodeWithText("Register").assertIsNotEnabled()
            compose.onNodeWithText("Sign In").assertIsNotEnabled()
            compose.onNodeWithContentDescription("Debug logs").assertIsEnabled()
        }
    }

    @Test
    fun terminalFailuresAllowRetry() {
        for (state in listOf("cancelled", "error", "rejected")) {
            withScenario(gallery(state)) {
                compose.onNodeWithText("Register").assertIsEnabled()
                compose.onNodeWithText("Sign In").assertIsEnabled()
            }
        }
    }

    @Test
    fun prfActionsFollowSessionAndCiphertextAvailability() {
        withScenario(gallery("unsupported")) {
            compose.onNodeWithText("Sign In + PRF").assertIsNotEnabled()
            compose.onNodeWithText("Encrypt").assertIsNotEnabled()
            compose.onNodeWithText("Decrypt").assertIsNotEnabled()
            compose.onNodeWithText("Sign Out").performScrollTo().assertIsEnabled()
        }
        withScenario(gallery("session")) {
            compose.onNodeWithText("Encrypt").assertIsEnabled()
            compose.onNodeWithText("Decrypt").assertIsNotEnabled()
        }
        withScenario(gallery("encrypted")) {
            compose.onNodeWithText("Decrypt").assertIsEnabled()
            compose.onNodeWithText("Decrypted message", substring = true).performScrollTo().assertIsDisplayed()
        }
    }

    @Test
    fun configurationExpansionSurvivesRecreation() {
        withScenario(gallery("auth")) { activity ->
            compose.onNodeWithText("Configuration").performScrollTo().performClick()
            compose.onNodeWithText("Relying party").performScrollTo().assertIsDisplayed()
            activity.recreate()
            compose.onNodeWithText("Relying party").performScrollTo().assertIsDisplayed()
        }
    }

    @Test
    fun messageRemainsEditableAndSurvivesGalleryRecreation() {
        withScenario(gallery("session")) { activity ->
            compose.onNodeWithText("The answer is 42").performScrollTo().performTextReplacement("My sample message")
            activity.recreate()
            compose.onNodeWithText("My sample message").performScrollTo().assertIsDisplayed()
        }
    }

    @Test
    fun largeTextKeepsAuthenticationAndConfigurationReachable() {
        withScenario(gallery("large-text")) {
            compose.onNodeWithText("Sign In").performScrollTo().assertIsDisplayed().assertIsEnabled()
            compose.onNodeWithText("Configuration").performScrollTo().performClick()
            compose.onNodeWithText("Relying party").performScrollTo().assertIsDisplayed()
        }
    }

    @Test
    fun longAndBidirectionalTextKeepSessionActionsReachable() {
        for (state in listOf("long-text", "rtl")) {
            withScenario(gallery(state)) {
                compose.onNode(hasText("שלום", substring = true) and hasSetTextAction().not())
                    .performScrollTo().assertIsDisplayed()
                compose.onNodeWithText("Sign Out").performScrollTo().assertIsDisplayed().assertIsEnabled()
            }
        }
    }

    companion object {
        private fun failureDirectory(): File {
            val output = InstrumentationRegistry.getArguments().getString("additionalTestOutputDir")
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            return if (output != null) {
                File(output, "ui-failures")
            } else {
                File(checkNotNull(context.getExternalFilesDir(null)), "ui-failures")
            }
        }

        @JvmStatic
        @BeforeClass
        fun removePreviousFixtureScreenshots() {
            val directory = failureDirectory()
            directory.listFiles()?.filter { it.extension == "png" }?.forEach { file ->
                check(file.delete()) { "Could not remove an old fixture screenshot" }
            }
        }
    }

    private fun withScenario(
        scenario: ActivityScenario<MainActivity>,
        block: (ActivityScenario<MainActivity>) -> Unit,
    ) {
        scenario.use {
            try {
                block(it)
            } catch (failure: Throwable) {
                // Capture while the app is still open; capture errors must preserve the test failure.
                val _ = runCatching {
                    val instrumentation = InstrumentationRegistry.getInstrumentation()
                    val directory = failureDirectory()
                    checkNotNull(directory).mkdirs()
                    val image = checkNotNull(instrumentation.uiAutomation.takeScreenshot())
                    try {
                        File(directory, "${testName.methodName}.png").outputStream().use { output ->
                            check(image.compress(Bitmap.CompressFormat.PNG, 100, output))
                        }
                    } finally {
                        image.recycle()
                    }
                }
                throw failure
            }
        }
    }

    private fun gallery(state: String): ActivityScenario<MainActivity> = ActivityScenario.launch(
        Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java).putExtra("sample-gallery", state),
    )
}
