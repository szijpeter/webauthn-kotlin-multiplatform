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
        root.resolve("documentation/examples/src/commonMain/Sample.kt").write(
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

            <!-- doc-example: id=greeting; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/Sample.kt#greeting -->
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
        assertContains(inventory, "documentation/examples/src/commonMain/Sample.kt#greeting")
        assertContains(inventory, "| compile |")
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
        root.resolve("documentation/examples/src/commonMain/Sample.kt").write(
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
             * source=documentation/examples/src/commonMain/Sample.kt#expression
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

    @Test
    fun `directive parser reports missing required fields with location`() = withRepository { root ->
        val fields = listOf("id", "owner", "verify", "audience")
        fields.forEach { missing ->
            root.resolve("README.md").write(
                """
                # Missing $missing

                <!-- doc-example: ${fields.filterNot { it == missing }.joinToString("; ") { "$it=${if (it == "id") "example" else if (it == "owner") "markdown" else if (it == "verify") "syntax" else "contributor"}" }} -->
                ```bash
                echo valid
                ```
                """,
            )
            val error = assertFailsWith<IllegalStateException> { DocumentationScanner(root).scan() }
            assertContains(error.message.orEmpty(), "README.md:3")
            assertContains(error.message.orEmpty(), missing)
        }
    }

    @Test
    fun `directive parser rejects duplicates unknown fields and blank values`() = withRepository { root ->
        val cases = listOf(
            "id=example; id=other; owner=markdown; verify=syntax; audience=contributor" to "duplicate",
            "id=example; owner=markdown; verify=syntax; audience=contributor; typo=value" to "unknown",
            "id=; owner=markdown; verify=syntax; audience=contributor" to "invalid",
        )
        cases.forEach { (directive, expected) ->
            root.resolve("README.md").write(
                """
                # Invalid directive

                <!-- doc-example: $directive -->
                ```bash
                echo invalid
                ```
                """,
            )
            val error = assertFailsWith<IllegalStateException> { DocumentationScanner(root).scan() }
            assertContains(error.message.orEmpty(), "README.md:3")
            assertContains(error.message.orEmpty(), expected)
        }
    }

    @Test
    fun `unclosed directives report file and line`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Unclosed

            <!-- doc-example: id=example; owner=markdown; verify=syntax; audience=contributor
            ```bash
            echo invalid
            ```
            """,
        )

        val error = assertFailsWith<IllegalStateException> { DocumentationScanner(root).scan() }
        assertContains(error.message.orEmpty(), "README.md:3")
        assertContains(error.message.orEmpty(), "unclosed doc-example directive")
    }

    @Test
    fun `invalid directive values report location`() = withRepository { root ->
        val cases = listOf(
            "id=BadId; owner=markdown; verify=syntax; audience=contributor" to "invalid id",
            "id=example; owner=unknown; verify=syntax; audience=contributor" to "unsupported owner",
            "id=example; owner=markdown; verify=unknown; audience=contributor" to "unsupported verification",
            "id=example; owner=markdown; verify=syntax; audience=unknown" to "unsupported audience",
        )
        cases.forEach { (field, expected) ->
            root.resolve("README.md").write(
                """
                # Invalid value

                <!-- doc-example: $field -->
                ```bash
                echo invalid
                ```
                """,
            )
            val error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
            assertContains(error.message.orEmpty(), "README.md:4")
            assertContains(error.message.orEmpty(), expected)
        }
    }

    @Test
    fun `fence parser supports matching backticks and tildes`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Fences

            <!-- doc-example: id=triple; owner=markdown; verify=syntax; audience=contributor -->
            ```bash
            echo triple
            ```

            <!-- doc-example: id=longer; owner=markdown; verify=syntax; audience=contributor -->
            ````bash
            echo longer
            ````

            <!-- doc-example: id=tilde; owner=markdown; verify=syntax; audience=contributor -->
            ~~~bash
            echo tilde
            ~~~
            """,
        )

        DocumentationVerifier(root).update()
        DocumentationVerifier(root).check()
    }

    @Test
    fun `unsupported mixed fence style cannot bypass the catalog`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Unsupported fence

            <!-- doc-example: id=mixed; owner=markdown; verify=syntax; audience=contributor -->
            ~``bash
            echo invalid
            ~``
            """,
        )

        val error = assertFailsWith<IllegalStateException> { DocumentationScanner(root).scan() }
        assertContains(error.message.orEmpty(), "unsupported fenced block style")
    }

    @Test
    fun `ownership and verification combinations are enforced`() {
        val validCases = listOf(
            Triple("markdown", "syntax", null),
            Triple("illustrative", "illustrative", null),
            Triple("configuration", "consumer-compile", "documentation/consumer-smoke/fixture.gradle.kts#fixture"),
            Triple("sample", "sample-build", "sample/compose-passkey/src/sample.kt#sample"),
            Triple("source", "compile", "documentation/examples/src/commonMain/source.kt#source"),
            Triple(
                "source",
                "unit",
                "documentation/examples/src/commonMain/kotlin/dev/webauthn/documentation/examples/ModelExample.kt#model-request-options",
            ),
            Triple(
                "source",
                "platform-compile",
                "documentation/examples/src/androidMain/Android.kt#android",
            ),
        )
        validCases.forEachIndexed { index, (owner, verification, source) ->
            withRepository { root ->
                if (source != null) {
                    val sourcePath = source.substringBefore('#')
                    root.resolve(sourcePath).write(
                        """
                        // docs-region ${source.substringAfter('#')}
                        println("example")
                        // docs-endregion ${source.substringAfter('#')}
                        """,
                    )
                }
                val reason = if (owner == "illustrative") "; reason=Rendered by Markdown" else ""
                root.resolve("README.md").write(
                    """
                    # Valid $index

                    <!-- doc-example: id=${if (verification == "unit") "core-webauthn-model-readme-kotlin-1" else "valid-$index"}; owner=$owner; verify=$verification; audience=consumer${source?.let { "; source=$it" }.orEmpty()}$reason -->
                    ```${if (owner == "markdown") "bash" else if (owner == "illustrative") "mermaid" else "kotlin"}
                    ${if (owner == "markdown") "echo example" else "println(\"example\")"}
                    ```
                    """,
                )
                DocumentationVerifier(root).update()
            }
        }

        val invalidCases = listOf(
            "owner=illustrative; verify=unit; audience=consumer; reason=No runtime" to "owner 'illustrative'",
            "owner=source; verify=consumer-compile; audience=consumer; source=documentation/examples/src/commonMain/source.kt#source" to "owner 'source'",
            "owner=markdown; verify=compile; audience=consumer" to "Kotlin examples must be backed by compiled source",
        )
        invalidCases.forEachIndexed { index, (fields, expected) ->
            withRepository { root ->
                root.resolve("documentation/examples/src/commonMain/source.kt").write(
                    """
                    // docs-region source
                    println("example")
                    // docs-endregion source
                    """,
                )
                root.resolve("README.md").write(
                    """
                    # Invalid $index

                    <!-- doc-example: id=invalid-$index; $fields -->
                    ```kotlin
                    println("example")
                    ```
                    """,
                )
                val error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
                assertContains(error.message.orEmpty(), expected)
            }
        }
    }

    @Test
    fun `source regions reject missing paths malformed ordering and empty content`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Missing source

            <!-- doc-example: id=missing-source; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/missing.kt#source -->
            ```kotlin
            println("example")
            ```
            """,
        )
        var error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
        assertContains(error.message.orEmpty(), "does not exist inside the repository")

        val outside = root.parent.resolve("${root.fileName}-outside.kt")
        outside.write(
            """
            // docs-region source
            println("outside")
            // docs-endregion source
            """,
        )
        try {
            root.resolve("README.md").write(
                """
                # Escaping source

                <!-- doc-example: id=escaping-source; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/../../../../${outside.fileName}#source -->
                ```kotlin
                println("example")
                ```
                """,
            )
            error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
            assertContains(error.message.orEmpty(), "does not exist inside the repository")
        } finally {
            Files.deleteIfExists(outside)
        }

        root.resolve("documentation/examples/src/commonMain/source.kt").write(
            """
            // docs-endregion source
            // docs-region source
            // docs-region source
            // docs-endregion source
            """,
        )
        root.resolve("README.md").write(
            """
            # Malformed source

            <!-- doc-example: id=malformed-source; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/source.kt#source -->
            ```kotlin
            println("example")
            ```
            """,
        )
        error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
        assertContains(error.message.orEmpty(), "expected one ordered source region")

        root.resolve("documentation/examples/src/commonMain/source.kt").write(
            """
            // docs-region source
            // docs-endregion source
            """,
        )
        error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
        assertContains(error.message.orEmpty(), "must not be empty")
    }

    @Test
    fun `stale and missing inventories fail check and table values are escaped`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Inventory

            <!-- doc-example: id=pipe-reason; owner=illustrative; verify=illustrative; audience=consumer; reason=Use | in the rendered diagram -->
            ```mermaid
            flowchart LR
            A --> B
            ```
            """,
        )
        val verifier = DocumentationVerifier(root)
        verifier.update()
        val inventory = root.resolve("documentation/example-inventory.md")
        assertContains(inventory.readText(), "Use \\| in the rendered diagram")

        inventory.writeText("stale\n")
        var error = assertFailsWith<IllegalStateException> { verifier.check() }
        assertContains(error.message.orEmpty(), "inventory is stale")

        Files.delete(inventory)
        error = assertFailsWith<IllegalStateException> { verifier.check() }
        assertContains(error.message.orEmpty(), "Missing generated inventory")
    }

    @Test
    fun `duplicate ids and deterministic ordering are enforced`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # First

            <!-- doc-example: id=duplicate; owner=markdown; verify=syntax; audience=contributor -->
            ```bash
            echo first
            ```

            <!-- doc-example: id=duplicate; owner=markdown; verify=syntax; audience=contributor -->
            ```bash
            echo second
            ```
            """,
        )
        val error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
        assertContains(error.message.orEmpty(), "Duplicate documentation example ids")
    }

    @Test
    fun `ordinary Kotlin strings containing fences are ignored`() = withRepository { root ->
        root.resolve("src/Api.kt").write(
            """
            package src

            val fence = "```kotlin"
            /**
             * <!-- doc-example: id=one; owner=markdown; verify=syntax; audience=contributor -->
             * ```bash
             * echo one
             * ```
             */
            fun api(): String = fence
            """,
        )

        val blocks = DocumentationScanner(root).scan()
        assertEquals(1, blocks.size)
        assertEquals("one", blocks.single().directive.id)
    }

    @Test
    fun `source region errors identify missing and duplicate markers`() = withRepository { root ->
        val cases = listOf(
            Triple("missing-end", """
                // docs-region source
                println("example")
            """, "expected one ordered source region"),
            Triple("duplicate-end", """
                // docs-region source
                println("example")
                // docs-endregion source
                // docs-endregion source
            """, "expected one ordered source region"),
            Triple("mismatched-end", """
                // docs-region source
                println("example")
                // docs-endregion other
            """, "expected one ordered source region"),
        )
        cases.forEach { (name, source, expected) ->
            root.resolve("documentation/examples/src/commonMain/source.kt").write(source)
            root.resolve("README.md").write(
                """
                # Source $name

                <!-- doc-example: id=$name; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/source.kt#source -->
                ```kotlin
                println("example")
                ```
                """,
            )
            val error = assertFailsWith<IllegalStateException> { DocumentationVerifier(root).update() }
            assertContains(error.message.orEmpty(), expected)
        }
    }

    @Test
    fun `stale markdown source content fails check until regenerated`() = withRepository { root ->
        root.resolve("documentation/examples/src/commonMain/source.kt").write(
            """
            // docs-region source
            println("fresh")
            // docs-endregion source
            """,
        )
        root.resolve("README.md").write(
            """
            # Stale

            <!-- doc-example: id=stale; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/source.kt#source -->
            ```kotlin
            println("old")
            ```
            """,
        )
        val verifier = DocumentationVerifier(root)
        verifier.update()
        root.resolve("README.md").writeText(root.resolve("README.md").readText().replace("println(\"fresh\")", "println(\"old\")"))

        val error = assertFailsWith<IllegalStateException> { verifier.check() }
        assertContains(error.message.orEmpty(), "source-backed block is stale")
    }

    @Test
    fun `multiple KDoc blocks and Markdown headings retain their context`() = withRepository { root ->
        root.resolve("src/Api.kt").write(
            """
            package src

            /**
             * First section
             * <!-- doc-example: id=kdoc-one; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/source.kt#one -->
             * ```kotlin
             * println("one")
             * ```
             */
            fun one() = Unit

            /**
             * Second section
             * <!-- doc-example: id=kdoc-two; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/commonMain/source.kt#two -->
             * ```kotlin
             * println("two")
             * ```
             */
            fun two() = Unit
            """,
        )
        root.resolve("documentation/examples/src/commonMain/source.kt").write(
            """
            // docs-region one
            println("one")
            // docs-endregion one
            // docs-region two
            println("two")
            // docs-endregion two
            """,
        )
        val blocks = DocumentationScanner(root).scan()
        assertEquals(listOf("kdoc-one", "kdoc-two"), blocks.map { it.directive.id })

        root.resolve("README.md").write(
            """
            # First heading
            <!-- doc-example: id=heading-one; owner=markdown; verify=syntax; audience=consumer -->
            ```bash
            echo one
            ```
            ## Second heading
            <!-- doc-example: id=heading-two; owner=markdown; verify=syntax; audience=consumer -->
            ```bash
            echo two
            ```
            """,
        )
        val markdownBlocks = DocumentationScanner(root).scan()
        assertEquals("First heading", markdownBlocks[0].purpose)
        assertEquals("Second heading", markdownBlocks[1].purpose)
    }

    @Test
    fun `a directive separated from its fence is reported as unmanaged`() = withRepository { root ->
        root.resolve("README.md").write(
            """
            # Detached

            <!-- doc-example: id=detached; owner=markdown; verify=syntax; audience=consumer -->
            explanatory content
            ```bash
            echo detached
            ```
            """,
        )

        val error = assertFailsWith<IllegalStateException> { DocumentationScanner(root).scan() }
        assertContains(error.message.orEmpty(), "Unmanaged documentation blocks")
    }

    @Test
    fun `inventory order follows file and opening line order`() = withRepository { root ->
        root.resolve("z.md").write(
            """
            # Z
            <!-- doc-example: id=z; owner=markdown; verify=syntax; audience=consumer -->
            ```bash
            echo z
            ```
            """,
        )
        root.resolve("a.md").write(
            """
            # A
            <!-- doc-example: id=a; owner=markdown; verify=syntax; audience=consumer -->
            ```bash
            echo a
            ```
            """,
        )
        DocumentationVerifier(root).update()
        val rows = Files.readAllLines(root.resolve("documentation/example-inventory.md"))
            .filter { it.startsWith("| ") }
            .drop(2)
        assertEquals("a", rows[0].substringAfter("| ").substringBefore(" |"))
        assertEquals("z", rows[1].substringAfter("| ").substringBefore(" |"))
    }

    private fun withRepository(block: (Path) -> Unit) {
        val root = createTempDirectory("documentation-verifier-test-")
        try {
            block(root)
        } finally {
            Files.walk(root).use { paths ->
                paths
                    .sorted(Comparator.reverseOrder())
                    .forEach(Files::deleteIfExists)
            }
        }
    }

    private fun Path.write(content: String) {
        parent?.createDirectories()
        writeText(content.trimIndent() + "\n")
    }
}
