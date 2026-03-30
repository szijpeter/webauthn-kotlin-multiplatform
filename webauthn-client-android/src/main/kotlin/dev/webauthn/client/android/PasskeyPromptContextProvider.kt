package dev.webauthn.client.android

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import java.util.concurrent.atomic.AtomicReference

/**
 * Provides a current UI-capable [Context] for passkey ceremonies.
 *
 * Passkey prompts require an Activity-backed context. This indirection allows retained objects
 * (for example ViewModels) to hold a stable client while the UI host is recreated.
 */
public fun interface PasskeyPromptContextProvider {
    public fun currentContextOrNull(): Context?
}

/** Fixed-context provider for apps that keep a stable Activity host. */
public class StaticPasskeyPromptContextProvider(
    private val context: Context,
) : PasskeyPromptContextProvider {
    override fun currentContextOrNull(): Context = context
}

/**
 * Thread-safe, updateable [PasskeyPromptContextProvider] for UI layers (Compose, Activities).
 */
public class MutablePasskeyPromptContextProvider(
    initial: Context? = null,
) : PasskeyPromptContextProvider {
    private val ref: AtomicReference<Context?> = AtomicReference(initial)

    override fun currentContextOrNull(): Context? = ref.get()

    public fun update(context: Context?) {
        ref.set(context)
    }
}

/**
 * Application-wide provider that tracks the currently resumed activity.
 *
 * This enables retained clients to resolve fresh prompt context after activity recreation.
 */
public class ForegroundActivityPasskeyPromptContextProvider private constructor(
    application: Application,
) : PasskeyPromptContextProvider, Application.ActivityLifecycleCallbacks {
    private val activityRef: AtomicReference<Activity?> = AtomicReference(null)

    init {
        application.registerActivityLifecycleCallbacks(this)
    }

    override fun currentContextOrNull(): Context? {
        val activity = activityRef.get() ?: return null
        return if (activity.isDestroyed || activity.isFinishing) null else activity
    }

    override fun onActivityResumed(activity: Activity) {
        activityRef.set(activity)
    }

    override fun onActivityPaused(activity: Activity) {
        if (activityRef.get() === activity) {
            activityRef.set(null)
        }
    }

    override fun onActivityDestroyed(activity: Activity) {
        if (activityRef.get() === activity) {
            activityRef.set(null)
        }
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

    override fun onActivityStarted(activity: Activity) = Unit

    override fun onActivityStopped(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

    private fun seedFromContext(contextHint: Context?) {
        val activity = contextHint?.findActivityOrNull() ?: return
        activityRef.set(activity)
    }

    /** Shared provider registry keyed by [Application]. */
    public companion object {
        private val lock: Any = Any()
        private val providers: MutableMap<Application, ForegroundActivityPasskeyPromptContextProvider> = mutableMapOf()

        /**
         * Returns a singleton provider for [application], optionally seeding it with [contextHint].
         */
        public fun forApplication(
            application: Application,
            contextHint: Context? = null,
        ): ForegroundActivityPasskeyPromptContextProvider {
            val provider = synchronized(lock) {
                providers[application]
                    ?: ForegroundActivityPasskeyPromptContextProvider(application).also {
                        providers[application] = it
                    }
            }
            provider.seedFromContext(contextHint)
            return provider
        }
    }
}

private fun Context.findActivityOrNull(): Activity? {
    var cursor: Context? = this
    while (cursor is ContextWrapper) {
        if (cursor is Activity) {
            return cursor
        }
        cursor = cursor.baseContext
    }
    return cursor as? Activity
}
