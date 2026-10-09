package com.vmp.packer

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Small Android Keystore-backed store for short-lived secrets and passwords. */
object SecretStore {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    fun encrypt(alias: String, value: CharArray): String {
        val clear = String(value).toByteArray(Charsets.UTF_8)
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key(alias))
            val ciphertext = cipher.doFinal(clear)
            val combined = ByteArray(cipher.iv.size + ciphertext.size)
            cipher.iv.copyInto(combined)
            ciphertext.copyInto(combined, cipher.iv.size)
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } finally {
            clear.fill(0)
        }
    }

    fun decrypt(alias: String, encoded: String): CharArray {
        val combined = Base64.decode(encoded, Base64.NO_WRAP)
        require(combined.size > IV_BYTES) { "Invalid encrypted secret" }
        val iv = combined.copyOfRange(0, IV_BYTES)
        val ciphertext = combined.copyOfRange(IV_BYTES, combined.size)
        val clear = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key(alias),
                GCMParameterSpec(TAG_BITS, iv)
            )
            cipher.doFinal(ciphertext)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
        return try {
            String(clear, Charsets.UTF_8).toCharArray()
        } finally {
            clear.fill(0)
        }
    }

    fun delete(alias: String) {
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply {
                load(null)
                if (containsAlias(alias)) deleteEntry(alias)
            }
        }
    }

    private fun key(alias: String): SecretKey {
        require(alias.matches(Regex("[A-Za-z0-9_.-]+"))) { "Invalid secret alias" }
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(alias)) {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply {
                init(
                    KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build()
                )
                generateKey()
            }
        }
        return keyStore.getKey(alias, null) as? SecretKey
            ?: error("Android Keystore secret is unavailable")
    }
}
