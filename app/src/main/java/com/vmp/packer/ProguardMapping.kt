package com.vmp.packer

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/** A source member name and the name emitted into the obfuscated DEX. */
data class ProguardMemberMapping(
    val originalName: String,
    val obfuscatedName: String
)

/** One unindented class record from a ProGuard/R8 mapping file. */
data class ProguardClassMapping(
    val originalName: String,
    val obfuscatedName: String,
    val members: List<ProguardMemberMapping> = emptyList()
)

/**
 * The subset of the ProGuard/R8 mapping format needed by the packer.
 *
 * R8 emits extra JSON-like comments for versioning, source files, synthesized
 * methods, outlines, and inlining. They are deliberately ignored here: this
 * model is used to answer DEX name-membership questions, not to retrace a
 * stack trace. Unknown comments and future records must not turn into class or
 * member records accidentally.
 */
class ProguardMapping private constructor(
    val classes: List<ProguardClassMapping>,
    val version: String?,
    val warnings: List<String>,
    /** SHA-256 of the exact UTF-8 mapping text, including comments/newlines. */
    val fingerprint: String
) {
    val classCount: Int
        get() = classes.size

    private val byObfuscatedName: Map<String, List<ProguardClassMapping>> =
        classes.groupBy { it.obfuscatedName }
    private val byOriginalName: Map<String, List<ProguardClassMapping>> =
        classes.groupBy { it.originalName }

    /** Original descriptors represented by an obfuscated DEX descriptor. */
    fun originalDescriptorsForObfuscated(descriptor: String): List<String> {
        val name = descriptorToName(descriptor) ?: return emptyList()
        return byObfuscatedName[name].orEmpty()
            .map { nameToDescriptor(it.originalName) }
            .distinct()
    }

    /** Obfuscated descriptors represented by an original source descriptor. */
    fun obfuscatedDescriptorsForOriginal(descriptor: String): List<String> {
        val name = descriptorToName(descriptor) ?: return emptyList()
        return byOriginalName[name].orEmpty()
            .map { nameToDescriptor(it.obfuscatedName) }
            .distinct()
    }

    /**
     * Return all source method names that may have emitted [obfuscatedMethod]
     * on the obfuscated class [descriptor].
     */
    fun originalMethodNamesForObfuscated(
        descriptor: String,
        obfuscatedMethod: String
    ): Set<String> {
        val name = descriptorToName(descriptor) ?: return emptySet()
        return byObfuscatedName[name].orEmpty()
            .flatMap { mapping ->
                mapping.members.filter { it.obfuscatedName == obfuscatedMethod }
                    .map { it.originalName }
            }
            .toSet()
    }

    /** Return emitted member names for one original source method. */
    fun obfuscatedMethodNamesForOriginal(
        descriptor: String,
        originalMethod: String
    ): Set<String> {
        val name = descriptorToName(descriptor) ?: return emptySet()
        return byOriginalName[name].orEmpty()
            .flatMap { mapping ->
                mapping.members.filter { it.originalName == originalMethod }
                    .map { it.obfuscatedName }
            }
            .toSet()
    }

    /** Prefer the first source class when a compiler emitted duplicate records. */
    fun primaryOriginalDescriptorForObfuscated(descriptor: String): String? =
        originalDescriptorsForObfuscated(descriptor).firstOrNull()

    companion object {
        private const val MAX_SUPPORTED_VERSION = 2.2
        private val VERSION_PATTERN = Regex(
            """['\"]id['\"]\s*:\s*['\"]com\.android\.tools\.r8\.mapping['\"]\s*,\s*['\"]version['\"]\s*:\s*['\"]([^'\"]+)['\"]"""
        )
        private val LEADING_LINE_RANGE = Regex("""^\d+:\d+:""")
        private val TRAILING_LINE_RANGE = Regex(""":\d+:\d+$""")

        /** Decode a bounded mapping file strictly as UTF-8, then parse it. */
        fun parseUtf8(bytes: ByteArray): ProguardMapping {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            return parse(decoder.decode(ByteBuffer.wrap(bytes)).toString())
        }

        /** Parse UTF-8-decoded mapping text without depending on the R8 runtime. */
        fun parse(text: String): ProguardMapping {
            require(text.isNotBlank()) { "mapping file is empty" }

            val parsed = ArrayList<ProguardClassMapping>()
            val warnings = ArrayList<String>()
            var currentOriginal: String? = null
            var currentObfuscated: String? = null
            var currentMembers = ArrayList<ProguardMemberMapping>()
            var version: String? = null

            fun finishClass() {
                val original = currentOriginal
                val obfuscated = currentObfuscated
                if (original != null && obfuscated != null) {
                    parsed += ProguardClassMapping(original, obfuscated, currentMembers.toList())
                }
                currentOriginal = null
                currentObfuscated = null
                currentMembers = ArrayList()
            }

            for (rawLine in text.removePrefix("\uFEFF").lineSequence()) {
                val line = rawLine.removeSuffix("\r")
                if (line.isBlank()) continue
                val trimmed = line.trimStart()
                if (trimmed.startsWith("#")) {
                    val match = VERSION_PATTERN.find(trimmed)
                    if (match != null) {
                        val parsedVersion = match.groupValues[1]
                        version = parsedVersion
                        val numeric = parsedVersion.toDoubleOrNull()
                        if (numeric != null && numeric > MAX_SUPPORTED_VERSION) {
                            warnings += "mapping version $version is newer than supported $MAX_SUPPORTED_VERSION"
                        }
                    }
                    continue
                }

                // Class records are the only non-indented records. A member line
                // may also contain "->", so checking indentation is important.
                if (!line[0].isWhitespace()) {
                    val arrow = line.indexOf(" -> ")
                    val colon = if (arrow >= 0) line.indexOf(':', arrow + 4) else -1
                    if (arrow > 0 && colon > arrow) {
                        val original = line.substring(0, arrow).trim()
                        val obfuscated = line.substring(arrow + 4, colon).trim()
                        if (isClassName(original) && isClassName(obfuscated)) {
                            finishClass()
                            currentOriginal = original
                            currentObfuscated = obfuscated
                            continue
                        }
                    }
                    // Unknown top-level records are ignored. They may be a
                    // future format extension or a diagnostic line.
                    continue
                }

                if (currentOriginal == null) continue
                val arrow = line.indexOf(" -> ")
                if (arrow <= 0) continue
                val obfuscated = line.substring(arrow + 4)
                    .substringBefore(" #")
                    .trim()
                    .substringBefore(' ')
                if (obfuscated.isEmpty()) continue

                val signature = line.substring(0, arrow).trim()
                    .replaceFirst(LEADING_LINE_RANGE, "")
                    .replace(TRAILING_LINE_RANGE, "")
                val openParen = signature.indexOf('(')
                if (openParen <= 0) continue // fields are not needed by policy
                val beforeParameters = signature.substring(0, openParen).trim()
                val qualifiedMethod = beforeParameters.substringAfterLast(' ')
                val methodName = qualifiedMethod.substringAfterLast('.')
                if (methodName.isNotEmpty() && isMemberName(methodName)) {
                    currentMembers += ProguardMemberMapping(methodName, obfuscated)
                }

            }
            finishClass()

            require(parsed.isNotEmpty()) { "mapping file contains no class mappings" }
            return ProguardMapping(
                classes = parsed,
                version = version,
                warnings = warnings.distinct(),
                fingerprint = sha256(text.toByteArray(Charsets.UTF_8))
            )
        }

        private fun isClassName(value: String): Boolean =
            value.isNotEmpty() && value.none { it.isWhitespace() || it == ':' || it == '#' }

        private fun isMemberName(value: String): Boolean =
            value.isNotEmpty() && value.none { it.isWhitespace() || it == ':' || it == '#' }

        private fun descriptorToName(descriptor: String): String? {
            if (descriptor.length < 3 || descriptor.first() != 'L' || descriptor.last() != ';')
                return null
            return descriptor.substring(1, descriptor.length - 1).replace('/', '.')
        }

        private fun nameToDescriptor(name: String): String =
            "L${name.replace('.', '/')};"

        private fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
    }
}
