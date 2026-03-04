package dev.webauthn.samples.composepasskey.android

import android.util.Log
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import dev.webauthn.samples.composepasskey.App

private const val TAG: String = "PasskeyDemo"

public class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "MainActivity.onCreate")
        Log.i(TAG, "MainActivity.setContent")
        setContent {
            App()
        }
    }
}
