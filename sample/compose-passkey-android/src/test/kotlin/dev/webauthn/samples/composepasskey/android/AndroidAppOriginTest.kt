package dev.webauthn.samples.composepasskey.android

import kotlin.test.Test
import kotlin.test.assertEquals

class AndroidAppOriginTest {
    @Test
    fun derives_android_origin_from_signing_certificate() {
        val origin = androidApkKeyHashOrigin("demo signing certificate".encodeToByteArray())

        assertEquals(
            "android:apk-key-hash:dq6yglJSBPNx57jffGnnlZMWYfYqLMkq1pQ3HIXibpg",
            origin,
        )
    }
}
