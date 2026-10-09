package com.vmp.packer

import java.io.File
import java.util.zip.ZipFile

/**
 * Which ABIs the input declares and whether this packer covers them all. */
object AbiPreflight {

    /** Legacy single-ABI name retained for callers that display a default. */
    const val DEFAULT_ABI = "arm64-v8a"
    internal val DEFAULT_ABIS = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

    /**
     * The packer asset holding the prebuilt libVMP for one ABI, or null when we
     * ship no build for it. Single source of truth for the coverage check, the
     * capability probe and the loader: a new target means editing here plus
     * native/CMakeLists.txt and build_libffi.sh.
     */
    fun vmcAssetFor(abi: String): String? = when (abi) {
        "arm64-v8a"   -> "vmp/libVMP-arm64-v8a.so"
        "armeabi-v7a" -> "vmp/libVMP-armeabi-v7a.so"
        "x86"         -> "vmp/libVMP-x86.so"
        "x86_64"      -> "vmp/libVMP-x86_64.so"
        else -> null
    }

    /** ABIs declared by the input's lib/<abi> native-library entries, in
     *  first-seen order, deduped. No native libraries at all means all
     *  supported runtime ABIs, because a Java-only input is architecture-neutral.
     */
    fun declaredAbis(input: File): List<String> {
        val found = ArrayList<String>()
        ZipFile(input).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val name = entries.nextElement().name
                if (name.startsWith("lib/") && name.endsWith(".so")) {
                    val parts = name.split('/')
                    if (parts.size >= 2) found.add(parts[1])
                }
            }
        }
        val abis = found.distinct()
        return if (abis.isEmpty()) DEFAULT_ABIS else abis
    }

    /**
     * One "abi: reason" line per ABI this packer cannot cover, in input order;
     * empty means every declared ABI has a libVMP in [packerAssetNames] (bare
     * file names).
     *
     * A refusal, not a warning: with one ABI missing the output looks fine on
     * covered devices and fails only on the others - loadLibrary("VMP") errors,
     * initVM never runs, every virtualized method throws UnsatisfiedLinkError.
     */
    fun uncovered(abis: List<String>, packerAssetNames: List<String>): List<String> {
        val out = ArrayList<String>()
        for (abi in abis) {
            val asset = vmcAssetFor(abi)
            when {
                asset == null -> out.add("$abi: no libVMP build exists for this ABI")
                !packerAssetNames.contains(asset.substringAfterLast('/')) ->
                    out.add("$abi: $asset is not in the packer assets")
            }
        }
        return out
    }

    /** Refusal text for uncovered ABIs. Partial output is never allowed. */
    fun refusal(uncovered: List<String>): String =
        "Unsupported ABI coverage:\n" +
                uncovered.joinToString("\n") { "  - $it" } +
                "\nPacking is refused because the output would fail on those devices.\n" +
                "Fix: add the matching libVMP asset or remove the ABI."
}
