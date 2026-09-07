package dev.webauthn.samples.composepasskey.android

import android.content.Intent
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivitySmokeTest {
    @get:Rule val compose = createEmptyComposeRule()

    @Test
    fun liveAppExposesAuthenticationAndDismissibleLogs() {
        ActivityScenario.launch(MainActivity::class.java).use {
            compose.onNodeWithText("Register").assertIsDisplayed().assertIsEnabled()
            compose.onNodeWithText("Sign In").assertIsEnabled()
            compose.onNodeWithText("Debug logs").performClick()
            compose.onNodeWithText("Done").assertIsDisplayed().performClick()
            compose.onNodeWithText("Register").assertIsDisplayed()
        }
    }

    @Test
    fun busyCeremonyDisablesBothActionsButKeepsDiagnosticsAvailable() {
        gallery("busy").use {
            compose.onNodeWithText("Register").assertIsNotEnabled()
            compose.onNodeWithText("Sign In").assertIsNotEnabled()
            compose.onNodeWithText("Debug logs").assertIsEnabled()
        }
    }

    @Test
    fun terminalFailuresAllowRetry() {
        for (state in listOf("cancelled", "error", "rejected")) {
            gallery(state).use {
                compose.onNodeWithText("Register").assertIsEnabled()
                compose.onNodeWithText("Sign In").assertIsEnabled()
            }
        }
    }

    @Test
    fun prfActionsFollowSessionAndCiphertextAvailability() {
        gallery("unsupported").use {
            compose.onNodeWithText("Sign In + PRF").assertIsNotEnabled()
            compose.onNodeWithText("Encrypt").assertIsNotEnabled()
            compose.onNodeWithText("Decrypt").assertIsNotEnabled()
            compose.onNodeWithText("Sign Out").performScrollTo().assertIsEnabled()
        }
        gallery("session").use {
            compose.onNodeWithText("Encrypt").assertIsEnabled()
            compose.onNodeWithText("Decrypt").assertIsNotEnabled()
        }
        gallery("encrypted").use {
            compose.onNodeWithText("Decrypt").assertIsEnabled()
            compose.onNodeWithText("Decrypted message", substring = true).performScrollTo().assertIsDisplayed()
        }
    }

    @Test
    fun configurationExpansionSurvivesRecreation() {
        gallery("auth").use { activity ->
            compose.onNodeWithText("Configuration  +").performScrollTo().performClick()
            compose.onNodeWithText("Relying party").performScrollTo().assertIsDisplayed()
            activity.recreate()
            compose.onNodeWithText("Relying party").performScrollTo().assertIsDisplayed()
        }
    }

    @Test
    fun messageRemainsEditableAndSurvivesGalleryRecreation() {
        gallery("session").use { activity ->
            compose.onNodeWithText("The answer is 42").performScrollTo().performTextReplacement("My sample message")
            activity.recreate()
            compose.onNodeWithText("My sample message").performScrollTo().assertIsDisplayed()
        }
    }

    private fun gallery(state: String): ActivityScenario<MainActivity> = ActivityScenario.launch(
        Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java).putExtra("sample-gallery", state),
    )
}
