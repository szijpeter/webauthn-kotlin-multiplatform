package dev.webauthn.model

import kotlin.test.Test
import kotlin.test.assertTrue

class TypesTest {
    @Test
    fun rpIdRequiresLowercaseHostLikeString() {
        val result = RpId.parse("Example.COM")
        assertTrue(result is ValidationResult.Invalid)
    }

    @Test
    fun challengeRequiresAtLeast16Bytes() {
        val result = Challenge.parse("YWJj")
        assertTrue(result is ValidationResult.Invalid)
    }
}
