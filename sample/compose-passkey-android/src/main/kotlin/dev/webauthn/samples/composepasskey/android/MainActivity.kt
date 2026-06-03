package dev.webauthn.samples.composepasskey.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import dev.webauthn.samples.composepasskey.app.App

private const val ANDROID_17_API_LEVEL = 37
private const val LOCAL_NETWORK_PERMISSION_REQUEST_CODE = ANDROID_17_API_LEVEL

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestLocalNetworkPermissionIfNeeded()
        setContent {
            App()
        }
    }

    private fun requestLocalNetworkPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < ANDROID_17_API_LEVEL) return
        if (!BuildConfig.WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION) return
        if (checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) return

        requestPermissions(
            arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK),
            LOCAL_NETWORK_PERMISSION_REQUEST_CODE,
        )
    }
}
