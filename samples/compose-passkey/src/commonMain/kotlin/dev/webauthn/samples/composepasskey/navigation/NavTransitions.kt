package dev.webauthn.samples.composepasskey.navigation

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.togetherWith
import androidx.navigation3.scene.Scene
import androidx.navigationevent.NavigationEvent

internal fun <T : Any> noTransitionSpec(): AnimatedContentTransitionScope<Scene<T>>.() -> ContentTransform {
    return {
        EnterTransition.None togetherWith ExitTransition.None
    }
}

internal fun <T : Any> noPredictiveTransitionSpec():
    AnimatedContentTransitionScope<Scene<T>>.(@NavigationEvent.SwipeEdge Int) -> ContentTransform {
    return {
        EnterTransition.None togetherWith ExitTransition.None
    }
}
