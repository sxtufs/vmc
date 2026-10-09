package com.vmp.packer

/**
 * One pack's selection rules as an immutable value, derived from the input APK's
 * manifest and its vmp/ prefix assets. VirtualizationPolicy keeps the stateless
 * vocabulary (library prefixes, lifecycle-critical names, Context wrappers); this
 * carries the per-input decisions, so no setting can outlive the pack that set it.

 */
data class PackPolicy(
    /** Descriptor package prefixes such as "Lcom/foo/bar/". */
    val targetPrefixes: Set<String> = emptySet(),
    /** False = whitelist inactive, so the legacy blacklist decides. */
    val targetsConfigured: Boolean = false,
    val excludeClassPrefixes: Set<String> = emptySet(),
    val excludeMethods: Set<String> = emptySet(),
    /** "Lcom/foo/Bar;->methodName" for methods reachable before the first initVM
     *  hook; virtualizing one leaves a stub with no registered implementation. */
    val clinitExempt: Set<String> = emptySet(),
    val minInsnsUnits: Int = DEFAULT_MIN_INSNS_UNITS,
    /** Optional original-to-obfuscated names from the input build's mapping.txt. */
    val mapping: ProguardMapping? = null,
) {

    /** Active exclusions, formatted for the pack log. Empty when none. */
    val activeExcludes: String
        get() = (excludeClassPrefixes + excludeMethods).joinToString(", ")

    fun withClinitExempt(keys: Set<String>): PackPolicy = copy(clinitExempt = keys)

    fun withMinInsnsUnits(units: Int): PackPolicy = copy(minInsnsUnits = units)

    /**
     * True when [desc] belongs to the input app itself and may be virtualized.
     * With an active whitelist this is a pure prefix match; without one the
     * legacy blacklist decides.
     */
    fun isTargetAppClass(desc: String): Boolean {
        val candidates = matchingDescriptors(desc)
        if (targetsConfigured) {
            return candidates.any { candidate ->
                targetPrefixes.any { candidate.startsWith(it) }
            }
        }
        return candidates.any { candidate ->
            val name = if (candidate.length >= 2 && candidate[0] == 'L' &&
                    candidate[candidate.length - 1] == ';') {
                candidate.substring(1, candidate.length - 1)
            } else candidate
            VirtualizationPolicy.LIBRARY_PREFIXES.none { name.startsWith(it) } &&
                    VirtualizationPolicy.KNOWN_SDK_PREFIXES.none { name.startsWith(it) }
        }
    }

    /** Match policy rules against both emitted and source descriptors. */
    private fun matchingDescriptors(desc: String): Sequence<String> = sequence {
        yield(desc)
        mapping?.originalDescriptorsForObfuscated(desc)?.forEach { yield(it) }
    }

    private fun isExcludedClass(desc: String): Boolean =
        matchingDescriptors(desc).any { candidate ->
            excludeClassPrefixes.any { candidate.startsWith(it) }
        }

    private fun isExcludedMethod(desc: String, methodName: String): Boolean {
        if (excludeMethods.contains("$desc->$methodName")) return true
        val sourceDescriptors = mapping?.originalDescriptorsForObfuscated(desc).orEmpty()
        val sourceNames = mapping?.originalMethodNamesForObfuscated(desc, methodName).orEmpty()
        return sourceDescriptors.any { sourceDesc ->
            excludeMethods.contains("$sourceDesc->$methodName") ||
                    sourceNames.any { sourceName ->
                        excludeMethods.contains("$sourceDesc->$sourceName")
                    }
        }
    }

    /**
     * Selection rule shared with DexRewriter: has code
     * (implied by caller), not an interface method, not a constructor, not
     * framework-lifecycle-critical, not a Context-wrapper factory, not a
     * malformed-frame method, and in one of the input app's own packages
     * (whitelist-first, so the renamed library stack keeps real Java bodies).
     * Declines are recorded in [skips] for the log.
     *
     * VmcWriter's code table and DexRewriter's native stubs both go through this
     * one function, which is the point: the ffi registration index is positional,
     * so if the two ever select different methods, one extra or missing entry
     * shifts every later one and dispatch jumps to the wrong closure -> crash.
     */
    fun shouldVirtualize(
        definingClass: String,
        methodName: String,
        paramTypesConcat: String,
        returnType: String,
        isInterface: Boolean,
        isConstructor: Boolean,
        instructionCount: Int = 0,
        registersSize: Int = 0,
        insSize: Int = 0,
        outsSize: Int = 0,
        skips: SkipLog,
        unsupportedOpcode: String? = null,
        isSynthetic: Boolean = false
    ): Boolean {
        if (isExcludedClass(definingClass)) return false
        if (isExcludedMethod(definingClass, methodName)) return false
        if (clinitExempt.contains("$definingClass->$methodName")) return false
        if (isSynthetic) return false
        val eligible = !isInterface && !isConstructor &&
                !VirtualizationPolicy.isFrameworkCriticalMethod(methodName) &&
                !VirtualizationPolicy.isContextWrapperMethod(paramTypesConcat, returnType) &&
                isTargetAppClass(definingClass)
        if (eligible && unsupportedOpcode != null) {
            skips.unsupportedOpcodeSkipped.add(
                "$definingClass->$methodName ($unsupportedOpcode)"
            )
            return false
        }
        if (eligible && (insSize > registersSize || instructionCount < 0)) {
            skips.frameSkipped.add("$definingClass->$methodName")
            return false
        }
        if (eligible && minInsnsUnits > 0 &&
                instructionCount in 1 until minInsnsUnits &&
                returnType != "Z") {
            skips.floorSkipped.add("$definingClass->$methodName")
            return false
        }
        return eligible
    }

    companion object {
        const val DEFAULT_MIN_INSNS_UNITS = 5

        /**
         * Derive the whitelist and exclusions for one input APK. [manifestPackage]
         * and [applicationClass] come from [AxmlPatcher.readTargets]; [extraLines]
         * are caller-supplied policy lines, currently used for saved UI exclusions.
         * Deriving nothing leaves
         * the whitelist inactive, so the legacy blacklist applies instead of
         * silently protecting nothing.
         *
         * A '!' line excludes without changing the whitelist:
         *   !com.pkg.Cls              whole class, and its inner classes
         *   !com.pkg.Cls->methodName  one method
         * The class part may also be an "Lcom/pkg/Cls;" descriptor or a package
         * path ending in '/'.
         */
        fun derive(
            manifestPackage: String?,
            applicationClass: String?,
            extraLines: List<String> = emptyList(),
            mapping: ProguardMapping? = null
        ): PackPolicy {
            val prefixes = LinkedHashSet<String>()
            val classExcludes = LinkedHashSet<String>()
            val methodExcludes = LinkedHashSet<String>()

            fun addDotted(pkg: String?) {
                val raw = pkg?.trim() ?: return
                if (raw.isEmpty()) return
                if (raw.startsWith("L") && raw.endsWith(";")) {
                    prefixes.add(raw)
                    return
                }
                val path = raw.replace('.', '/').trimEnd('/')
                if (path.isNotEmpty()) prefixes.add("L$path/")
            }

            fun parseExclude(body: String) {
                val arrow = body.indexOf("->")
                if (arrow > 0) {
                    val cls = body.substring(0, arrow).trim()
                    val mn = body.substring(arrow + 2).trim()
                    if (cls.isEmpty() || mn.isEmpty()) return
                    val desc = if (cls.startsWith("L") && cls.endsWith(";")) cls
                               else "L${cls.replace('.', '/')};"
                    methodExcludes.add("$desc->$mn")
                    return
                }
                val raw = body.trim()
                if (raw.isEmpty()) return
                val desc = if (raw.startsWith("L") && raw.endsWith(";")) raw
                           else "L${raw.replace('.', '/').trimEnd('/')};"
                val path = desc.substring(1, desc.length - 1)
                classExcludes.add(desc)
                classExcludes.add("L$path\$")
                classExcludes.add("L$path/")
            }

            addDotted(manifestPackage)

            val app = applicationClass?.trim()
            if (!app.isNullOrEmpty()) {
                if (app.startsWith("L") && app.endsWith(";")) {
                    val inner = app.substring(1, app.length - 1)
                    addDotted(inner.substringBeforeLast('/'))
                    prefixes.add(app)
                } else {
                    addDotted(app.substringBeforeLast('.'))
                    prefixes.add("L${app.replace('.', '/')};")
                }
            }

            for (line in extraLines) {
                val l = line.trim()
                if (l.isEmpty() || l.startsWith("#")) continue
                if (l.startsWith("!")) {
                    parseExclude(l.substring(1).trim())
                    continue
                }
                addDotted(l)
            }

            return PackPolicy(
                targetPrefixes = prefixes,
                targetsConfigured = prefixes.isNotEmpty(),
                excludeClassPrefixes = classExcludes,
                excludeMethods = methodExcludes,
                mapping = mapping,
            )
        }
    }
}

/** Methods declined during one pack or scan, grouped for the pack log. */
class SkipLog {
    val floorSkipped = LinkedHashSet<String>()
    val frameSkipped = LinkedHashSet<String>()
    val unsupportedOpcodeSkipped = LinkedHashSet<String>()
}
