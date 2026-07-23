package dev.webauthn.documentation

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolute
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempFile
import kotlin.io.path.extension
import kotlin.io.path.invariantSeparatorsPathString
import kotlin.io.path.isDirectory
import kotlin.io.path.name
import kotlin.io.path.readText
import kotlin.io.path.writeText

private const val INVENTORY_PATH = "documentation/example-inventory.md"
private const val DIRECTIVE_PREFIX = "<!-- doc-example:"
private const val DIRECTIVE_SUFFIX = "-->"
private val ID_PATTERN = Regex("[a-z0-9][a-z0-9-]*")
private val OPEN_FENCE_PATTERN = Regex("^```([A-Za-z0-9_+-]*)\\s*$")
private val SOURCE_REGION_PATTERN = Regex("^\\s*//\\s*docs-region\\s+([a-z0-9][a-z0-9-]*)\\s*$")
private val SOURCE_END_PATTERN = Regex("^\\s*//\\s*docs-endregion\\s+([a-z0-9][a-z0-9-]*)\\s*$")

/** Command-line entry point for documentation catalog verification and regeneration. */
public object DocumentationExamples {
    @JvmStatic
    public fun main(args: Array<String>) {
        require(args.size == 2) {
            "Usage: DocumentationExamples <check|update> <repository-root>"
        }

        val mode = Mode.entries.firstOrNull { it.cliName == args[0] }
            ?: error("Unknown mode '${args[0]}'; expected check or update")
        val root = Path.of(args[1]).absolute().normalize()
        val verifier = DocumentationVerifier(root)

        when (mode) {
            Mode.CHECK -> verifier.check()
            Mode.UPDATE -> verifier.update()
        }
    }
}

internal enum class Mode(internal val cliName: String) {
    CHECK("check"),
    UPDATE("update"),
}

internal data class Directive(
    val id: String,
    val owner: String,
    val verification: String,
    val audience: String,
    val source: String?,
    val reason: String?,
)

internal data class DocumentationBlock(
    val file: Path,
    val relativeFile: String,
    val directiveLine: Int,
    val openingLine: Int,
    val bodyStartIndex: Int,
    val bodyEndIndex: Int,
    val prefix: String,
    val language: String,
    val purpose: String,
    val directive: Directive,
    val content: String,
)

internal class DocumentationVerifier(private val root: Path) {
    private val scanner = DocumentationScanner(root)

    fun check() {
        val blocks = scanner.scan()
        validate(blocks)

        val expectedInventory = renderInventory(blocks)
        val inventory = root.resolve(INVENTORY_PATH)
        check(Files.exists(inventory)) {
            "Missing generated inventory $INVENTORY_PATH; run ./gradlew docsUpdate"
        }
        check(inventory.readText() == expectedInventory) {
            "Documentation example inventory is stale; run ./gradlew docsUpdate"
        }

        println("Documentation examples: PASS (${blocks.size} managed blocks)")
    }

    fun update() {
        var blocks = scanner.scan()
        validateStructure(blocks)
        validatePublicationIsolation()
        updateSourceBackedBlocks(blocks)

        blocks = scanner.scan()
        validate(blocks)
        val inventory = root.resolve(INVENTORY_PATH)
        inventory.parent.createDirectories()
        inventory.writeText(renderInventory(blocks))
        println("Documentation examples updated (${blocks.size} managed blocks)")
    }

    private fun validate(blocks: List<DocumentationBlock>) {
        validateStructure(blocks)
        validatePublicationIsolation()
        blocks.forEach { block ->
            validateSourceSynchronization(block)
            validateSyntax(block)
        }
    }

    private fun validateStructure(blocks: List<DocumentationBlock>) {
        check(blocks.isNotEmpty()) { "No managed documentation blocks found" }

        val duplicateIds = blocks.groupBy { it.directive.id }.filterValues { it.size > 1 }
        check(duplicateIds.isEmpty()) {
            "Duplicate documentation example ids: ${duplicateIds.keys.sorted().joinToString()}"
        }

        blocks.forEach { block ->
            val directive = block.directive
            check(ID_PATTERN.matches(directive.id)) {
                "${block.location()}: invalid id '${directive.id}'"
            }
            check(directive.owner in setOf("markdown", "source", "sample", "configuration", "illustrative")) {
                "${block.location()}: unsupported owner '${directive.owner}'"
            }
            check(
                directive.verification in setOf(
                    "syntax",
                    "compile",
                    "consumer-compile",
                    "unit",
                    "integration",
                    "platform-compile",
                    "sample-build",
                    "device-manual",
                    "illustrative",
                ),
            ) {
                "${block.location()}: unsupported verification '${directive.verification}'"
            }
            check(directive.audience in setOf("consumer", "contributor", "maintainer")) {
                "${block.location()}: unsupported audience '${directive.audience}'"
            }

            val sourceBacked = directive.owner in setOf("source", "sample", "configuration")
            check(sourceBacked == (directive.source != null)) {
                "${block.location()}: ${directive.owner} ownership requires exactly one source"
            }
            if (directive.owner == "illustrative" || directive.verification in setOf("device-manual", "illustrative")) {
                check(!directive.reason.isNullOrBlank()) {
                    "${block.location()}: illustrative/manual examples require a reason"
                }
            }
            if (block.language == "kotlin") {
                check(directive.owner != "markdown") {
                    "${block.location()}: Kotlin examples must be backed by compiled source or configuration"
                }
            }
        }
    }

    private fun validatePublicationIsolation() {
        val documentationRoot = root.resolve("documentation")
        if (Files.exists(documentationRoot)) {
            val prohibited = Files.walk(documentationRoot).use { paths ->
                paths
                    .filter { Files.isRegularFile(it) && it.fileName.toString() == "build.gradle.kts" }
                    .filter { buildFile ->
                        val text = Files.readString(buildFile)
                        "maven-publish" in text ||
                            "webauthn.published-library" in text ||
                            "webauthn.published-platform" in text
                    }
                    .map { root.relativize(it).invariantSeparatorsPathString }
                    .sorted()
                    .toList()
            }
            check(prohibited.isEmpty()) {
                "Documentation projects must not apply publication plugins: ${prohibited.joinToString()}"
            }
        }

        val bomBuild = root.resolve("platform/bom/build.gradle.kts")
        if (Files.exists(bomBuild)) {
            val text = Files.readString(bomBuild)
            check(":documentation:" !in text && "documentation-" !in text) {
                "Documentation projects must not enter the public BOM"
            }
        }
    }

    private fun updateSourceBackedBlocks(blocks: List<DocumentationBlock>) {
        blocks.filter { it.directive.source != null }.groupBy { it.file }.forEach { (file, fileBlocks) ->
            val lines = Files.readAllLines(file).toMutableList()
            fileBlocks
                .sortedByDescending { it.bodyStartIndex }
                .forEach { block ->
                    val source = extractSource(block)
                    val replacement = source.lines().map { line ->
                        if (block.prefix.isEmpty()) line else block.prefix + line
                    }
                    lines.subList(block.bodyStartIndex, block.bodyEndIndex).clear()
                    lines.addAll(block.bodyStartIndex, replacement)
                }
            file.writeText(lines.joinToString("\n") + "\n")
        }
    }

    private fun validateSourceSynchronization(block: DocumentationBlock) {
        if (block.directive.source == null) return
        val expected = extractSource(block)
        check(block.content == expected) {
            "${block.location()}: source-backed block is stale; run ./gradlew docsUpdate"
        }
    }

    private fun extractSource(block: DocumentationBlock): String {
        val sourceSpec = requireNotNull(block.directive.source)
        val pathText = sourceSpec.substringBefore('#')
        val regionId = sourceSpec.substringAfter('#', missingDelimiterValue = "")
        check(pathText.isNotBlank() && regionId.isNotBlank()) {
            "${block.location()}: source must use path#region syntax"
        }
        check(ID_PATTERN.matches(regionId)) {
            "${block.location()}: invalid source region '$regionId'"
        }

        val sourcePath = root.resolve(pathText).normalize()
        check(sourcePath.startsWith(root) && Files.isRegularFile(sourcePath)) {
            "${block.location()}: source file does not exist inside the repository: $pathText"
        }

        val lines = Files.readAllLines(sourcePath)
        val starts = lines.mapIndexedNotNull { index, line ->
            SOURCE_REGION_PATTERN.matchEntire(line)?.takeIf { it.groupValues[1] == regionId }?.let { index }
        }
        val ends = lines.mapIndexedNotNull { index, line ->
            SOURCE_END_PATTERN.matchEntire(line)?.takeIf { it.groupValues[1] == regionId }?.let { index }
        }
        check(starts.size == 1 && ends.size == 1 && starts.single() < ends.single()) {
            "${block.location()}: expected one ordered source region '$regionId' in $pathText"
        }
        return lines.subList(starts.single() + 1, ends.single())
            .joinToString("\n")
            .trimEnd()
    }

    private fun validateSyntax(block: DocumentationBlock) {
        if (block.directive.verification != "syntax") return
        check(block.language in setOf("bash", "sh")) {
            "${block.location()}: syntax verification is currently supported for shell blocks only"
        }

        val script = createTempFile(prefix = "webauthn-doc-example-", suffix = ".sh")
        try {
            script.writeText("set -e\n${block.content}\n")
            val process = ProcessBuilder("bash", "-n", script.toString())
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            check(process.waitFor() == 0) {
                "${block.location()}: shell syntax check failed:\n$output"
            }
        } finally {
            Files.deleteIfExists(script)
        }
    }

    private fun renderInventory(blocks: List<DocumentationBlock>): String {
        val header = """
            <!-- Generated by ./gradlew docsUpdate. Do not edit manually. -->
            # Documentation example inventory

            This inventory is generated from the inline `doc-example` directives. It records every user-facing fenced
            example, its single source of truth, and its strongest automated or explicitly manual verification level.

            Managed blocks: **${blocks.size}**

            | ID | File | Purpose | Language | Audience | Owner | Source of truth | Verification | Migration | Exception |
            | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
        """.trimIndent()

        val rows = blocks.sortedWith(compareBy({ it.relativeFile }, { it.openingLine })).joinToString("\n") { block ->
            val directive = block.directive
            val source = directive.source ?: when (directive.owner) {
                "markdown" -> "Markdown block"
                "illustrative" -> "Markdown illustration"
                else -> directive.owner
            }
            listOf(
                directive.id,
                "${block.relativeFile}:${block.openingLine}",
                block.purpose,
                block.language.ifBlank { "plain" },
                directive.audience,
                directive.owner,
                source,
                directive.verification,
                "complete",
                directive.reason.orEmpty(),
            ).joinToString(" | ", prefix = "| ", postfix = " |") { escapeTable(it) }
        }

        return "$header\n$rows\n"
    }

    private fun escapeTable(value: String): String {
        return value.replace("|", "\\|").replace("\n", " ").trim()
    }

    private fun DocumentationBlock.location(): String = "$relativeFile:$openingLine"
}

internal class DocumentationScanner(private val root: Path) {
    fun scan(): List<DocumentationBlock> {
        val candidates = Files.walk(root).use { paths ->
            paths
                .filter { Files.isRegularFile(it) }
                .filter { it.extension == "md" || it.extension == "kt" }
                .filter { !isExcluded(it) }
                .sorted()
                .toList()
        }

        val blocks = candidates.flatMap(::parseFile)
        val unmanaged = blocks.filter { it.directive.id == UNMANAGED_ID }
        check(unmanaged.isEmpty()) {
            unmanaged.joinToString(
                prefix = "Unmanaged documentation blocks found:\n",
                separator = "\n",
            ) { "  ${it.relativeFile}:${it.openingLine} (${it.language.ifBlank { "plain" }})" }
        }
        return blocks
    }

    @Suppress("CyclomaticComplexMethod", "LongMethod", "LoopWithTooManyJumpStatements")
    internal fun parseFile(file: Path): List<DocumentationBlock> {
        val relative = root.relativize(file).invariantSeparatorsPathString
        val lines = Files.readAllLines(file)
        val isKotlin = file.extension == "kt"
        val blocks = mutableListOf<DocumentationBlock>()
        var heading = if (isKotlin) "KDoc example" else file.name
        var pendingDirective: Pair<Int, Directive>? = null
        var index = 0
        var inKDoc = false

        while (index < lines.size) {
            if (isKotlin) {
                val trimmed = lines[index].trimStart()
                if (!inKDoc) {
                    inKDoc = trimmed.startsWith("/**")
                    index += 1
                    continue
                }
                if (trimmed.endsWith("*/")) {
                    inKDoc = false
                    pendingDirective = null
                    index += 1
                    continue
                }
            }
            val normalized = normalize(lines[index], isKotlin)
            if (!isKotlin && normalized.startsWith("#")) {
                heading = normalized.trimStart('#').trim().ifBlank { heading }
            }

            readDirective(lines, index, isKotlin)?.let { (directive, nextIndex) ->
                pendingDirective = index to directive
                index = nextIndex
                return@let
            } ?: run {
                if (pendingDirective?.first == index) return@run
                val fence = OPEN_FENCE_PATTERN.matchEntire(normalized)
                if (fence == null || isKotlin && !looksLikeKDocLine(lines[index])) {
                    if (normalized.isNotBlank()) {
                        pendingDirective = null
                    }
                    index += 1
                    return@run
                }

                val openingIndex = index
                val prefix = lines[index].substringBefore("```")
                index += 1
                val bodyStart = index
                while (
                    index < lines.size &&
                    OPEN_FENCE_PATTERN.matchEntire(normalize(lines[index], isKotlin)) == null
                ) {
                    index += 1
                }
                check(index < lines.size) { "$relative:${openingIndex + 1}: unclosed code fence" }
                val bodyEnd = index
                val directiveEntry = pendingDirective
                val directive = directiveEntry?.second ?: unmanagedDirective(relative, openingIndex + 1)
                val content = lines.subList(bodyStart, bodyEnd)
                    .joinToString("\n") { stripBodyPrefix(it, prefix, isKotlin) }
                    .trimEnd()

                blocks += DocumentationBlock(
                    file = file,
                    relativeFile = relative,
                    directiveLine = (directiveEntry?.first ?: openingIndex) + 1,
                    openingLine = openingIndex + 1,
                    bodyStartIndex = bodyStart,
                    bodyEndIndex = bodyEnd,
                    prefix = prefix,
                    language = fence.groupValues[1].lowercase(),
                    purpose = heading,
                    directive = directive,
                    content = content,
                )
                pendingDirective = null
                index += 1
            }
        }
        return blocks
    }

    private fun readDirective(
        lines: List<String>,
        startIndex: Int,
        isKotlin: Boolean,
    ): Pair<Directive, Int>? {
        if (!normalize(lines[startIndex], isKotlin).startsWith(DIRECTIVE_PREFIX)) return null

        var endIndex = startIndex
        while (
            endIndex < lines.size &&
            !normalize(lines[endIndex], isKotlin).endsWith(DIRECTIVE_SUFFIX)
        ) {
            endIndex += 1
        }
        check(endIndex < lines.size) { "Unclosed doc-example directive at line ${startIndex + 1}" }
        val text = lines.subList(startIndex, endIndex + 1)
            .joinToString(" ") { normalize(it, isKotlin) }
        return requireNotNull(parseDirective(text)) to endIndex + 1
    }

    private fun parseDirective(line: String): Directive? {
        if (!line.startsWith(DIRECTIVE_PREFIX) || !line.endsWith(DIRECTIVE_SUFFIX)) return null
        val fields = line.removePrefix(DIRECTIVE_PREFIX)
            .removeSuffix(DIRECTIVE_SUFFIX)
            .trim()
            .split(';')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .associate { field ->
                val key = field.substringBefore('=').trim()
                val value = field.substringAfter('=', missingDelimiterValue = "").trim()
                check(key.isNotBlank() && value.isNotBlank()) { "Invalid doc-example directive field '$field'" }
                key to value
            }

        val known = setOf("id", "owner", "verify", "audience", "source", "reason")
        check(fields.keys.all { it in known }) {
            "Unknown doc-example directive fields: ${(fields.keys - known).sorted().joinToString()}"
        }
        return Directive(
            id = fields.getValue("id"),
            owner = fields.getValue("owner"),
            verification = fields.getValue("verify"),
            audience = fields.getValue("audience"),
            source = fields["source"],
            reason = fields["reason"],
        )
    }

    private fun isExcluded(path: Path): Boolean {
        val relative = root.relativize(path).invariantSeparatorsPathString
        if (relative == INVENTORY_PATH) return true
        if (relative.startsWith("documentation/tooling/src/test/")) return true
        return relative.split('/').any {
            it in setOf(".git", ".gradle", ".gradle-local", "build")
        }
    }

    private fun normalize(line: String, kotlin: Boolean): String {
        if (!kotlin) return line.trim()
        val trimmed = line.trimStart()
        return if (trimmed.startsWith("*")) trimmed.removePrefix("*").trimStart() else trimmed
    }

    private fun looksLikeKDocLine(line: String): Boolean = line.trimStart().startsWith("*")

    private fun stripBodyPrefix(line: String, prefix: String, kotlin: Boolean): String {
        if (!kotlin) return line.removePrefix(prefix)
        val trimmed = line.trimStart()
        if (!trimmed.startsWith("*")) return line
        return trimmed.removePrefix("*").removePrefix(" ")
    }

    private fun unmanagedDirective(relative: String, line: Int): Directive {
        return Directive(
            id = UNMANAGED_ID,
            owner = "illustrative",
            verification = "illustrative",
            audience = "contributor",
            source = null,
            reason = "$relative:$line",
        )
    }

    private companion object {
        const val UNMANAGED_ID = "__unmanaged__"
    }
}
