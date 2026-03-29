package dev.webauthn.samples.composepasskey

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import dev.webauthn.samples.composepasskey.navigation.AppRoute
import dev.webauthn.samples.composepasskey.navigation.NavBackStackConfig
import dev.webauthn.samples.composepasskey.navigation.noPredictiveTransitionSpec
import dev.webauthn.samples.composepasskey.navigation.noTransitionSpec
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography
import org.koin.compose.navigation3.koinEntryProvider
import org.koin.core.annotation.KoinExperimentalAPI

@OptIn(KoinExperimentalAPI::class)
@Composable
internal fun SampleAppRoot() {
    val backStack = rememberNavBackStack(
        configuration = NavBackStackConfig,
        AppRoute.Auth,
    )
    val entryProvider = koinEntryProvider<NavKey>()

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
                entryProvider = entryProvider,
            )
        }
    }
}
