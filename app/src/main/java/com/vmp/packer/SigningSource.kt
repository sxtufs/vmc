package com.vmp.packer

import java.io.File

/** The source used for one APK signing operation. */
sealed interface SigningSource {
    data class Generated(val identityTag: String?) : SigningSource

    /**
     * The password exists only for the duration of the pack request. Callers
     * must clear it after the signer has been resolved.
     */
    data class ImportedJks(
        val file: File,
        val alias: String,
        val password: CharArray
    ) : SigningSource {
        fun clearPassword() = password.fill('\u0000')
    }
}
