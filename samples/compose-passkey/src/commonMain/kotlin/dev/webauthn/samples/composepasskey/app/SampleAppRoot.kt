package dev.webauthn.samples.composepasskey.app

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import dev.webauthn.samples.composepasskey.app.navigation.AppRoute
import dev.webauthn.samples.composepasskey.app.navigation.NavBackStackConfig
import dev.webauthn.samples.composepasskey.data.logging.DebugLogStore
import dev.webauthn.samples.composepasskey.data.session.AppSessionState
import dev.webauthn.samples.composepasskey.data.session.AppSessionStore
import dev.webauthn.samples.composepasskey.ui.components.DebugLogSheet
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography
import org.koin.compose.koinInject
import org.koin.compose.navigation3.koinEntryProvider
import org.koin.core.annotation.KoinExperimentalAPI

@OptIn(KoinExperimentalAPI::class, ExperimentalMaterial3Api::class)
@Composable
internal fun SampleAppRoot() {
    val sessionStore: AppSessionStore = koinInject()
    val debugLogs: DebugLogStore = koinInject()
    val sessionState by sessionStore.state.collectAsState()
    var showDebugSheet by remember { mutableStateOf(false) }
    val debugSheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

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
                if (backStack.size != 1 || backStack.lastOrNull() != AppRoute.Main) {
                    backStack.clear()
                    backStack += AppRoute.Main
                }
            }
        }
    }

    MaterialTheme(
        colorScheme = EditorialPalette,
        typography = EditorialTypography,
    ) {
        if (showDebugSheet) {
            DebugLogSheet(
                entries = debugLogs.entries,
                sheetState = debugSheetState,
                onDismissRequest = { showDebugSheet = false },
            )
        }
        Surface {
            CompositionLocalProvider(
                LocalShowDebugLogs provides { showDebugSheet = true },
            ) {
                NavDisplay(
                    backStack = backStack,
                    entryDecorators = listOf(
                        rememberSaveableStateHolderNavEntryDecorator(),
                        rememberViewModelStoreNavEntryDecorator(),
                    ),
                    entryProvider = entryProvider,
                )
            }
        }
    }
}
