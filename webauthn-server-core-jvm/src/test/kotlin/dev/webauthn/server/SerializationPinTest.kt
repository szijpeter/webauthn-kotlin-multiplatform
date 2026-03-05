package dev.webauthn.server

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SerializationPinTest {

    @Test
    fun kotlinxSerializationVersionRemainsPinnedTo19() {
        val tomlPath = findRepoRoot(Path.of("").absolute())
            ?.resolve("gradle")
            ?.resolve("libs.versions.toml")
        assertNotNull(
            tomlPath,
            "Could not locate gradle/libs.versions.toml. Keep serialization pinned to 1.9.0 until Signum issue #415 is resolved.",
        )

        val content = Files.readString(tomlPath)
        val match = Regex("""(?m)^serialization\s*=\s*"([^"]+)"""").find(content)
        val version = match?.groupValues?.getOrNull(1)
        assertEquals(
            "1.9.0",
            version,
            "kotlinx-serialization is pinned due Signum issue #415. If upgrading, first resolve upstream compatibility.",
        )
    }

    private fun findRepoRoot(start: Path): Path? {
        var current: Path? = start
        repeat(8) {
            val candidate = current ?: return null
            if (Files.exists(candidate.resolve("gradle").resolve("libs.versions.toml"))) {
                return candidate
            }
            current = candidate.parent
        }
        return null
    }
}
