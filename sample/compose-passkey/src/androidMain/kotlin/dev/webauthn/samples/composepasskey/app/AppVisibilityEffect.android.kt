package dev.webauthn.samples.composepasskey.app

import android.app.Activity
import android.content.ContextWrapper
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

@Composable
internal actual fun AppVisibilityEffect(
    onForeground: () -> Unit,
    onBackground: () -> Unit,
    onHostDisposed: () -> Unit,
) {
    val foreground = rememberUpdatedState(onForeground)
    val background = rememberUpdatedState(onBackground)
    val disposed = rememberUpdatedState(onHostDisposed)
    val owner = LocalLifecycleOwner.current
    val context = LocalContext.current
    DisposableEffect(owner, context) {
        val activity = generateSequence(context) { (it as? ContextWrapper)?.baseContext }
            .filterIsInstance<Activity>().firstOrNull()
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> foreground.value()
                Lifecycle.Event.ON_STOP -> if (activity?.isChangingConfigurations != true) background.value()
                else -> Unit
            }
        }
        owner.lifecycle.addObserver(observer)
        onDispose {
            owner.lifecycle.removeObserver(observer)
            if (activity?.isChangingConfigurations != true) disposed.value()
        }
    }
}
