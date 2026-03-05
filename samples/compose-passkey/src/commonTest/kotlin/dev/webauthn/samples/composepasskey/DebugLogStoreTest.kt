package dev.webauthn.samples.composepasskey

import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import kotlin.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DebugLogStoreTest {
    @Test
    fun stores_wall_clock_timestamp_and_payload_fields() {
        val store = DebugLogStore(maxEntries = 10)
        val before = Clock.System.now()

        store.i(source = "app", message = "hello")
        val after = Clock.System.now()

        val entry = store.entries.first()
        assertTrue(entry.timestamp >= before && entry.timestamp <= after)
        assertEquals(DebugLogLevel.INFO, entry.level)
        assertEquals("app", entry.source)
        assertEquals("hello", entry.message)
    }

    @Test
    fun keeps_newest_entries_first() {
        val store = DebugLogStore(maxEntries = 10)

        store.d(source = "http", message = "line 1")
        store.w(source = "controller", message = "line 2")

        assertEquals(2, store.entries.size)
        assertEquals("line 2", store.entries[0].message)
        assertEquals("line 1", store.entries[1].message)
    }

    @Test
    fun enforces_max_entries_limit() {
        val store = DebugLogStore(maxEntries = 2)

        store.i(source = "app", message = "one")
        store.i(source = "app", message = "two")
        store.i(source = "app", message = "three")

        assertEquals(2, store.entries.size)
        assertEquals("three", store.entries[0].message)
        assertEquals("two", store.entries[1].message)
    }

    @Test
    fun records_error_entries_with_throwable_input() {
        val store = DebugLogStore(maxEntries = 10)

        store.e(
            source = "controller",
            message = "verification failed",
            throwable = IllegalStateException("boom"),
        )

        val entry = store.entries.first()
        assertEquals(DebugLogLevel.ERROR, entry.level)
        assertEquals("controller", entry.source)
        assertEquals("verification failed", entry.message)
    }
}
