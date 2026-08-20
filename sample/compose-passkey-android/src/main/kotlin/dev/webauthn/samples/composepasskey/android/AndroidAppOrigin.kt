package dev.webauthn.samples.composepasskey.android

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest
import java.util.Base64

private const val ANDROID_APK_KEY_HASH_PREFIX = "android:apk-key-hash:"

@Suppress("DEPRECATION")
internal fun Context.androidAppOrigin(): String {
    val packageInfo = packageManager.getPackageInfo(
        packageName,
        PackageManager.GET_SIGNING_CERTIFICATES,
    )
    val signingCertificate = checkNotNull(packageInfo.signingInfo)
        .apkContentsSigners
        .singleOrNull()
    checkNotNull(signingCertificate) { "The installed Android app must have exactly one current signing certificate." }
    return androidApkKeyHashOrigin(signingCertificate.toByteArray())
}

internal fun androidApkKeyHashOrigin(signingCertificate: ByteArray): String {
    val fingerprint = MessageDigest.getInstance("SHA-256").digest(signingCertificate)
    val encodedFingerprint = Base64.getUrlEncoder().withoutPadding().encodeToString(fingerprint)
    return "$ANDROID_APK_KEY_HASH_PREFIX$encodedFingerprint"
}
