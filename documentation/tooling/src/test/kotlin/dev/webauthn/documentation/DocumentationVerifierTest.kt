package dev.webauthn.documentation

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DocumentationVerifierTest {
    @Test
    fun `update synchronizes source blocks and writes deterministic inventory`() = withRepository { root ->
        root.resolve("examples/Sample.kt").write(
            """
            package examples

            // docs-region greeting
            fun greeting(): String = "hello"
            // docs-endregion greeting
            """,
        )
        root.resolve("README.md").write(
            """
            # Greeting

            <!-- doc-example: id=greeting; owner=source; verify=consumer-compile; audience=consumer; source=examples/Sample.kt#greeting -->
            ```kotlin
            fun greeting(): String = "stale"
            ```
            """,
        )

        val verifier = DocumentationVerifier(root)
        verifier.update()
        verifier.check()

        assertContains(root.resolve("README.md").readText(), "fun greeting(): String = \"hello\"")
        val inventory = root.resolve("documentation/example-inventory.md").readText()
        assertContains(inventory, "Managed blocks: **1**")
        assertContains(inventory, "examples/Sample.kt#greeting")
        assertContains(inventory, "consumer-compile")
    }

    @Test
    fun `new unmanaged fence fails the catalog check`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Missing directive

            ```bash
            echo unmanaged
            ```
            """,
        )

        val error = assertFailsWith<IllegalStateException> {
            DocumentationScanner(root).scan()
        }
        assertContains(error.message.orEmpty(), "Unmanaged documentation blocks")
    }

    @Test
    fun `shell syntax verification rejects malformed commands`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Invalid shell

            <!-- doc-example: id=invalid-shell; owner=markdown; verify=syntax; audience=contributor -->
            ```bash
            if true; then
            ```
            """,
        )

        val error = assertFailsWith<IllegalStateException> {
            DocumentationVerifier(root).update()
        }
        assertContains(error.message.orEmpty(), "shell syntax check failed")
    }

    @Test
    fun `KDoc fences retain comment prefixes when updated`() = withRepository { root ->
        root.resolve("examples/Sample.kt").write(
            """
            package examples

            // docs-region expression
            check(listOf(1, 2).size == 2)
            // docs-endregion expression
            """,
        )
        root.resolve("src/Api.kt").write(
            """
            package src

            /**
             * Example:
             * <!-- doc-example:
             * id=kdoc-expression; owner=source; verify=compile; audience=consumer;
             * source=examples/Sample.kt#expression
             * -->
             * ```kotlin
             * check(false)
             * ```
             */
            fun api(): Unit = Unit
            """,
        )

        DocumentationVerifier(root).update()

        val updated = root.resolve("src/Api.kt").readText()
        assertContains(updated, " * check(listOf(1, 2).size == 2)")
        assertEquals(0, updated.lines().count { it.contains("docs-region expression") })
    }

    @Test
    fun `documentation projects cannot apply publication plugins`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            <!-- doc-example: id=safe-shell; owner=markdown; verify=syntax; audience=contributor -->
            ```bash
            echo safe
            ```
            """,
        )
        root.resolve("documentation/examples/build.gradle.kts").write(
            """
            plugins {
                `maven-publish`
            }
            """,
        )

        val error = assertFailsWith<IllegalStateException> {
            DocumentationVerifier(root).update()
        }
        assertContains(error.message.orEmpty(), "must not apply publication plugins")
    }

    private fun withRepository(block: (Path) -> Unit) {
        val root = createTempDirectory("documentation-verifier-test-")
        try {
            block(root)
        } finally {
            Files.walk(root)
                .sorted(Comparator.reverseOrder())
                .forEach(Files::deleteIfExists)
        }
    }

    private fun Path.write(content: String) {
        parent?.createDirectories()
        writeText(content.trimIndent() + "\n")
    }
}
