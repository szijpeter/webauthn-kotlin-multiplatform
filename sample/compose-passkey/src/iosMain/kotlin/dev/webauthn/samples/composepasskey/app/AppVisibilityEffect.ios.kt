package dev.webauthn.samples.composepasskey.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.rememberUpdatedState
import platform.Foundation.NSNotificationCenter
import platform.Foundation.NSOperationQueue
import platform.UIKit.UIApplicationDidEnterBackgroundNotification
import platform.UIKit.UIApplicationWillEnterForegroundNotification

@Composable
internal actual fun AppVisibilityEffect(
    onForeground: () -> Unit,
    onBackground: () -> Unit,
    onHostDisposed: () -> Unit,
) {
    val foreground = rememberUpdatedState(onForeground)
    val background = rememberUpdatedState(onBackground)
    val disposed = rememberUpdatedState(onHostDisposed)
    DisposableEffect(Unit) {
        val center = NSNotificationCenter.defaultCenter
        val backgroundObserver = center.addObserverForName(
            UIApplicationDidEnterBackgroundNotification, null, NSOperationQueue.mainQueue,
        ) { background.value() }
        val foregroundObserver = center.addObserverForName(
            UIApplicationWillEnterForegroundNotification, null, NSOperationQueue.mainQueue,
        ) { foreground.value() }
        onDispose {
            center.removeObserver(backgroundObserver)
            center.removeObserver(foregroundObserver)
            disposed.value()
        }
    }
}
