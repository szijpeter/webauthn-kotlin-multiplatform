package dev.webauthn.samples.composepasskey.android

import android.util.Log
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import dev.webauthn.samples.composepasskey.App
import dev.webauthn.samples.composepasskey.initializeComposePasskeySampleAppKoin

private const val TAG: String = "PasskeyDemo"

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        initializeComposePasskeySampleAppKoin(activity = this)
        Log.i(TAG, "MainActivity.onCreate")
        Log.i(TAG, "MainActivity.setContent")
        setContent {
            App()
        }
    }
}
