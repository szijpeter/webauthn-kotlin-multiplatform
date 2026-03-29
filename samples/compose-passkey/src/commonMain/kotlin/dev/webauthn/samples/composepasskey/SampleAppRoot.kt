package dev.webauthn.samples.composepasskey

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import dev.webauthn.samples.composepasskey.navigation.AppRoute
import dev.webauthn.samples.composepasskey.navigation.NavBackStackConfig
import dev.webauthn.samples.composepasskey.navigation.noPredictiveTransitionSpec
import dev.webauthn.samples.composepasskey.navigation.noTransitionSpec
import dev.webauthn.samples.composepasskey.session.AppSessionState
import dev.webauthn.samples.composepasskey.session.AppSessionStore
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography
import org.koin.compose.koinInject
import org.koin.compose.navigation3.koinEntryProvider
import org.koin.core.annotation.KoinExperimentalAPI

@OptIn(KoinExperimentalAPI::class)
@Composable
internal fun SampleAppRoot() {
    val sessionStore: AppSessionStore = koinInject()
    val sessionState by sessionStore.state.collectAsState()

    val backStack = rememberNavBackStack(
        configuration = NavBackStackConfig,
        AppRoute.Auth,
    )
    val entryProvider = koinEntryProvider<NavKey>()

    LaunchedEffect(sessionState) {
        when (sessionState) {
            AppSessionState.SignedOut -> {
                backStack.clear()
                backStack += AppRoute.Auth
            }

            is AppSessionState.SignedIn -> {
                if (backStack.lastOrNull() != AppRoute.LoggedIn) {
                    backStack += AppRoute.LoggedIn
                }
            }
        }
    }

    MaterialTheme(
        colorScheme = EditorialPalette,
        typography = EditorialTypography,
    ) {
        Surface {
            NavDisplay(
                backStack = backStack,
                transitionSpec = noTransitionSpec(),
                popTransitionSpec = noTransitionSpec(),
                predictivePopTransitionSpec = noPredictiveTransitionSpec(),
                entryDecorators = listOf(
                    rememberSaveableStateHolderNavEntryDecorator(),
                    rememberViewModelStoreNavEntryDecorator(),
                ),
                entryProvider = entryProvider,
            )
        }
    }
}
