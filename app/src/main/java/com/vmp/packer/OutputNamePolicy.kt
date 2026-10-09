package com.vmp.packer

/**
 * Validates output names before they are combined with the app-owned output
 * directory. Values derived from an input APK are untrusted just like UI input.
 */
object OutputNamePolicy {
    private val SAFE_APK_NAME = Regex("[A-Za-z0-9._-]{1,128}\\.apk")

    fun isSafeFileName(name: String): Boolean =
        name.isNotBlank() && name != "." && name != ".." &&
                SAFE_APK_NAME.matches(name)

    fun fromPackage(packageName: String?): String? {
        val pkg = packageName?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val candidate = "$pkg.apk"
        return candidate.takeIf(::isSafeFileName)
    }
}
