package dev.webauthn.client.android

import android.app.Activity
import android.app.Application
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class ForegroundActivityPasskeyPromptContextProviderTest {
    @Test
    fun forApplication_seeds_with_context_hint_activity() {
        val application = mockk<Application>(relaxed = true)
        val activity = mockActivity()

        val provider = ForegroundActivityPasskeyPromptContextProvider.forApplication(
            application = application,
            contextHint = activity,
        )

        assertSame(activity, provider.currentContextOrNull())
    }

    @Test
    fun resumed_activity_becomes_current_and_pause_clears_it() {
        val application = mockk<Application>(relaxed = true)
        val activity = mockActivity()
        val provider = ForegroundActivityPasskeyPromptContextProvider.forApplication(application)

        provider.onActivityResumed(activity)
        assertSame(activity, provider.currentContextOrNull())

        provider.onActivityPaused(activity)
        assertNull(provider.currentContextOrNull())
    }

    @Test
    fun finishing_or_destroyed_activity_is_not_returned() {
        val application = mockk<Application>(relaxed = true)
        var finishing = false
        var destroyed = false
        val activity = mockk<Activity>(relaxed = true).also {
            every { it.isFinishing } answers { finishing }
            every { it.isDestroyed } answers { destroyed }
        }
        val provider = ForegroundActivityPasskeyPromptContextProvider.forApplication(application)

        provider.onActivityResumed(activity)
        assertSame(activity, provider.currentContextOrNull())

        finishing = true
        assertNull(provider.currentContextOrNull())

        finishing = false
        destroyed = true
        assertNull(provider.currentContextOrNull())
    }

    private fun mockActivity(): Activity {
        return mockk<Activity>(relaxed = true).also {
            every { it.isFinishing } returns false
            every { it.isDestroyed } returns false
        }
    }
}
