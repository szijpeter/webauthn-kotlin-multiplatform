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
private const val MIN_FENCE_LENGTH = 3
private val ID_PATTERN = Regex("[a-z0-9][a-z0-9-]*")
private val FENCE_PATTERN = Regex("^([`~]{3,})([A-Za-z0-9_+-]*)\\s*$")
private val SOURCE_REGION_PATTERN = Regex("^\\s*//\\s*docs-region\\s+([a-z0-9][a-z0-9-]*)\\s*$")
private val SOURCE_END_PATTERN = Regex("^\\s*//\\s*docs-endregion\\s+([a-z0-9][a-z0-9-]*)\\s*$")
private val REQUIRED_DIRECTIVE_FIELDS = setOf("id", "owner", "verify", "audience")
private val KNOWN_DIRECTIVE_FIELDS = REQUIRED_DIRECTIVE_FIELDS + setOf("source", "reason")
private const val DOCUMENTATION_SOURCE_ROOT = "documentation/examples/src"
private const val CONSUMER_FIXTURE_SOURCE_ROOT = "documentation/consumer-smoke"
private const val BUILT_SAMPLE_SOURCE_ROOT = "sample/compose-passkey"
private const val MODEL_UNIT_SOURCE =
    "documentation/examples/src/commonMain/kotlin/" +
        "dev/webauthn/documentation/examples/ModelExample.kt#model-request-options"
private const val RUNTIME_UNIT_SOURCE =
    "documentation/examples/src/commonMain/kotlin/" +
        "dev/webauthn/documentation/examples/RuntimeExample.kt#runtime-cancellation"
private val UNIT_VERIFIED_SOURCES = mapOf(
    "core-webauthn-model-readme-kotlin-1" to MODEL_UNIT_SOURCE,
    "core-webauthn-runtime-core-readme-kotlin-1" to RUNTIME_UNIT_SOURCE,
)

private data class Fence(
    val marker: Char,
    val length: Int,
    val language: String,
)

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

@Suppress("TooManyFunctions")
internal class DocumentationVerifier(private val root: Path) {
    private val scanner = DocumentationScanner(root)
    private val realRoot = root.toRealPath()

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
        val sourceReferences = validateStructure(blocks)
        validatePublicationIsolation()
        updateSourceBackedBlocks(blocks, sourceReferences)

        blocks = scanner.scan()
        validate(blocks)
        val inventory = root.resolve(INVENTORY_PATH)
        inventory.parent.createDirectories()
        inventory.writeText(renderInventory(blocks))
        println("Documentation examples updated (${blocks.size} managed blocks)")
    }

    private fun validate(blocks: List<DocumentationBlock>) {
        val sourceReferences = validateStructure(blocks)
        validatePublicationIsolation()
        blocks.forEach { block ->
            validateSourceSynchronization(block, sourceReferences[block.directive.id])
            validateSyntax(block)
        }
    }

    private fun validateStructure(blocks: List<DocumentationBlock>): Map<String, SourceReference> {
        check(blocks.isNotEmpty()) { "No managed documentation blocks found" }

        val duplicateIds = blocks.groupBy { it.directive.id }.filterValues { it.size > 1 }
        check(duplicateIds.isEmpty()) {
            "Duplicate documentation example ids: ${duplicateIds.keys.sorted().joinToString()}"
        }

        val sourceReferences = mutableMapOf<String, SourceReference>()
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
                    "platform-compile",
                    "sample-build",
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
            if (directive.owner == "illustrative" || directive.verification == "illustrative") {
                check(!directive.reason.isNullOrBlank()) {
                    "${block.location()}: illustrative examples require a reason"
                }
            }
            if (block.language == "kotlin") {
                check(directive.owner != "markdown") {
                    "${block.location()}: Kotlin examples must be backed by compiled source or configuration"
                }
            }
            validateOwnershipAndVerification(block)?.let { sourceReferences[directive.id] = it }
        }
        return sourceReferences
    }

    private fun validateOwnershipAndVerification(block: DocumentationBlock): SourceReference? {
        val directive = block.directive
        val source = when (directive.owner) {
            "configuration" -> requireSourceUnder(block, CONSUMER_FIXTURE_SOURCE_ROOT)
            "sample" -> requireSourceUnder(block, BUILT_SAMPLE_SOURCE_ROOT)
            "source" -> requireSourceUnder(block, DOCUMENTATION_SOURCE_ROOT)
            else -> null
        }
        val allowed = when (directive.owner) {
            "markdown" -> setOf("syntax")
            "illustrative" -> setOf("illustrative")
            "configuration" -> setOf("consumer-compile")
            "sample" -> setOf("sample-build")
            "source" -> {
                if (isPlatformSource(requireNotNull(source))) {
                    setOf("platform-compile")
                } else {
                    setOf("compile", "unit")
                }
            }
            else -> emptySet()
        }
        check(directive.verification in allowed) {
            "${block.location()}: owner '${directive.owner}' cannot claim verification " +
                "'${directive.verification}'; expected one of ${allowed.sorted().joinToString()}"
        }
        if (directive.verification == "unit") {
            check(UNIT_VERIFIED_SOURCES[directive.id] == directive.source) {
                "${block.location()}: unit verification must match its allow-listed source region"
            }
        }
        return source
    }

    private fun requireSourceUnder(block: DocumentationBlock, allowedRoot: String): SourceReference {
        val source = parseSource(block)
        val lexicalAllowedRoot = root.resolve(allowedRoot).normalize()
        check(source.path.startsWith(lexicalAllowedRoot)) {
            "${block.location()}: ${block.directive.owner} source must be under $allowedRoot"
        }

        if (Files.exists(source.path)) {
            val realSource = source.path.toRealPath()
            val realAllowedRoot = lexicalAllowedRoot.toRealPath()
            check(realSource.startsWith(realAllowedRoot)) {
                "${block.location()}: ${block.directive.owner} source must resolve under $allowedRoot"
            }
            return source.copy(path = realSource)
        }
        return source
    }

    private fun isPlatformSource(source: SourceReference): Boolean {
        val sourcePath = source.path
        if (!sourcePath.startsWith(realRoot)) return false
        val relative = realRoot.relativize(sourcePath).invariantSeparatorsPathString
        return relative.contains("/src/androidMain/") ||
            relative.contains("/src/iosMain/") ||
            relative.contains("/src/platformMain/") ||
            relative.contains("/src/androidTest/") ||
            relative.contains("/src/iosTest/")
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

    private fun updateSourceBackedBlocks(
        blocks: List<DocumentationBlock>,
        sourceReferences: Map<String, SourceReference>,
    ) {
        blocks.filter { it.directive.source != null }.groupBy { it.file }.forEach { (file, fileBlocks) ->
            val lines = Files.readAllLines(file).toMutableList()
            fileBlocks
                .sortedByDescending { it.bodyStartIndex }
                .forEach { block ->
                    val source = extractSource(block, requireNotNull(sourceReferences[block.directive.id]))
                    val replacement = source.lines().map { line ->
                        if (block.prefix.isEmpty()) line else block.prefix + line
                    }
                    lines.subList(block.bodyStartIndex, block.bodyEndIndex).clear()
                    lines.addAll(block.bodyStartIndex, replacement)
                }
            file.writeText(lines.joinToString("\n") + "\n")
        }
    }

    private fun validateSourceSynchronization(block: DocumentationBlock, source: SourceReference?) {
        if (block.directive.source == null) return
        val expected = extractSource(block, requireNotNull(source))
        check(block.content == expected) {
            "${block.location()}: source-backed block is stale; run ./gradlew docsUpdate"
        }
    }

    private fun extractSource(block: DocumentationBlock, source: SourceReference): String {
        check(source.path.startsWith(realRoot) && Files.isRegularFile(source.path)) {
            "${block.location()}: source file does not exist inside the repository: ${source.pathText}"
        }

        val lines = Files.readAllLines(source.path)
        val starts = lines.mapIndexedNotNull { index, line ->
            SOURCE_REGION_PATTERN.matchEntire(line)?.takeIf { it.groupValues[1] == source.regionId }?.let { index }
        }
        val ends = lines.mapIndexedNotNull { index, line ->
            SOURCE_END_PATTERN.matchEntire(line)?.takeIf { it.groupValues[1] == source.regionId }?.let { index }
        }
        check(starts.size == 1 && ends.size == 1 && starts.single() < ends.single()) {
            "${block.location()}: expected one ordered source region '${source.regionId}' in ${source.pathText}"
        }
        val content = lines.subList(starts.single() + 1, ends.single())
            .joinToString("\n")
            .trimEnd()
        check(content.isNotBlank()) {
            "${block.location()}: source region '${source.regionId}' in ${source.pathText} must not be empty"
        }
        return content
    }

    private data class SourceReference(
        val pathText: String,
        val regionId: String,
        val path: Path,
    )

    private fun parseSource(block: DocumentationBlock): SourceReference {
        val sourceSpec = requireNotNull(block.directive.source)
        val pathText = sourceSpec.substringBefore('#')
        val regionId = sourceSpec.substringAfter('#', missingDelimiterValue = "")
        check(pathText.isNotBlank() && regionId.isNotBlank()) {
            "${block.location()}: source must use path#region syntax"
        }
        check(ID_PATTERN.matches(regionId)) {
            "${block.location()}: invalid source region '$regionId'"
        }
        return SourceReference(pathText, regionId, root.resolve(pathText).normalize())
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
            example, its single source of truth, and its strongest automated or illustrative verification level.

            Managed blocks: **${blocks.size}**

            | ID | File | Purpose | Language | Audience | Owner | Source of truth | Verification | Exception |
            | --- | --- | --- | --- | --- | --- | --- | --- | --- |
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

            readDirective(lines, index, isKotlin, relative)?.let { (directive, nextIndex) ->
                pendingDirective = index to directive
                index = nextIndex
                return@let
            } ?: run {
                if (pendingDirective?.first == index) return@run
                val fence = parseFence(normalized)
                if (fence == null || isKotlin && !looksLikeKDocLine(lines[index])) {
                    if (fenceCandidate(normalized)) {
                        check(false) {
                            "$relative:${index + 1}: unsupported fenced block style; " +
                                "use matching backtick or tilde fences"
                        }
                    }
                    if (normalized.isNotBlank()) {
                        pendingDirective = null
                    }
                    index += 1
                    return@run
                }

                val openingIndex = index
                val markerText = fence.marker.toString().repeat(fence.length)
                val prefix = lines[index].substringBefore(markerText)
                index += 1
                val bodyStart = index
                while (
                    index < lines.size &&
                    !isClosingFence(parseFence(normalize(lines[index], isKotlin)), fence)
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
                    language = fence.language.lowercase(),
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
        relative: String,
    ): Pair<Directive, Int>? {
        if (!normalize(lines[startIndex], isKotlin).startsWith(DIRECTIVE_PREFIX)) return null

        var endIndex = startIndex
        while (
            endIndex < lines.size &&
            !normalize(lines[endIndex], isKotlin).endsWith(DIRECTIVE_SUFFIX)
        ) {
            endIndex += 1
        }
        check(endIndex < lines.size) { "$relative:${startIndex + 1}: unclosed doc-example directive" }
        val text = lines.subList(startIndex, endIndex + 1)
            .joinToString(" ") { normalize(it, isKotlin) }
        return requireNotNull(parseDirective(text, "$relative:${startIndex + 1}")) to endIndex + 1
    }

    private fun parseDirective(line: String, location: String): Directive? {
        if (!line.startsWith(DIRECTIVE_PREFIX) || !line.endsWith(DIRECTIVE_SUFFIX)) return null
        val entries = line.removePrefix(DIRECTIVE_PREFIX)
            .removeSuffix(DIRECTIVE_SUFFIX)
            .trim()
            .split(';')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { field ->
                val key = field.substringBefore('=').trim()
                val value = field.substringAfter('=', missingDelimiterValue = "").trim()
                check(key.isNotBlank() && value.isNotBlank()) {
                    "$location: invalid doc-example directive field '$field'"
                }
                key to value
            }

        val duplicateKeys = entries.groupBy { it.first }.filterValues { it.size > 1 }.keys
        check(duplicateKeys.isEmpty()) {
            "$location: duplicate doc-example directive fields: ${duplicateKeys.sorted().joinToString()}"
        }
        val fields = entries.toMap()
        check(fields.keys.all { it in KNOWN_DIRECTIVE_FIELDS }) {
            "$location: unknown doc-example directive fields: " +
                "${(fields.keys - KNOWN_DIRECTIVE_FIELDS).sorted().joinToString()}"
        }
        val missingFields = REQUIRED_DIRECTIVE_FIELDS - fields.keys
        check(missingFields.isEmpty()) {
            "$location: missing required doc-example fields: ${missingFields.sorted().joinToString()}"
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

    private fun parseFence(line: String): Fence? {
        val match = FENCE_PATTERN.matchEntire(line) ?: return null
        val markerText = match.groupValues[1]
        if (markerText.any { it != markerText.first() }) return null
        return Fence(markerText.first(), markerText.length, match.groupValues[2])
    }

    private fun isClosingFence(candidate: Fence?, opening: Fence): Boolean {
        return candidate != null &&
            candidate.marker == opening.marker &&
            candidate.length >= opening.length &&
            candidate.language.isBlank()
    }

    private fun fenceCandidate(line: String): Boolean {
        val trimmed = line.trimStart()
        val markerRun = trimmed.takeWhile { it == '`' || it == '~' }
        return markerRun.length >= MIN_FENCE_LENGTH
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
