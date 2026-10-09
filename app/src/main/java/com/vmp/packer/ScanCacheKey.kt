package com.vmp.packer

import java.util.zip.CRC32

/**
 * Pure scan-cache key data. It combines the APK SHA-256, raw-content CRC32,
 * policy-asset text, optional mapping fingerprint, and a schema version so a
 * cached result is reused only when all inputs that affect the counted method
 * set are unchanged.
 */
object ScanCacheKey {
    private const val KEY_VERSION = "10"


    /**
     * CRC over the raw policy lines. Comments are included deliberately: the key
     * tracks the text, not its interpretation, so a comment-only asset edit
     * invalidates rather than persisting whatever the file used to mean.
     */
    fun policyCrc(lines: List<String>): Long = CRC32().apply {
        lines.forEach { line ->
            val bytes = line.toByteArray(Charsets.UTF_8)
            update(bytes.size and 0xff)
            update((bytes.size ushr 8) and 0xff)
            update((bytes.size ushr 16) and 0xff)
            update((bytes.size ushr 24) and 0xff)
            update(bytes)
        }
    }.value

    /** Includes a schema version so policy-derivation changes invalidate old scans. */
    fun of(
        shaHex: String,
        fileCrc: Long,
        policyLines: List<String>,
        mappingFingerprint: String? = null
    ): String =
        "$KEY_VERSION:$shaHex:$fileCrc:${policyCrc(policyLines)}:${mappingFingerprint ?: "-"}"
}
