package com.vmp.packer

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo

/**
 * Small read-only JKS loader for Android.
 *
 * Android does not expose the desktop JKS provider, so KeyStore.getInstance("JKS")
 * fails on-device. This reads the standard JKS v1/v2 envelope, verifies its
 * password digest, decrypts the standard JKS private-key entry, and delegates
 * PKCS#8/X.509 decoding to the platform and bundled BC ASN.1 classes.
 */
object JksReader {
    private const val MAGIC = 0xfeedfeed.toInt()
    private const val VERSION_1 = 1
    private const val VERSION_2 = 2
    private const val PRIVATE_KEY_ENTRY = 1
    private const val TRUSTED_CERT_ENTRY = 2
    private const val DIGEST_SIZE = 20
    private const val MAX_ENTRY_BYTES = 8 * 1024 * 1024
    private const val KEY_PROTECTOR_OID = "1.3.6.1.4.1.42.2.17.1.1"

    data class Result(
        val alias: String,
        val privateKey: PrivateKey,
        val certificateChain: List<X509Certificate>
    )

    fun load(input: InputStream, alias: String, password: CharArray): Result {
        require(alias.isNotBlank()) { "JKS alias is required" }
        val bytes = input.use { it.readBytes() }
        require(bytes.size > DIGEST_SIZE) { "JKS file is too small" }

        val passwordBytes = passwordBytes(password)
        val bodySize = bytes.size - DIGEST_SIZE
        val body = bytes.copyOfRange(0, bodySize)
        val expectedDigest = bytes.copyOfRange(bodySize, bytes.size)
        try {
            val digest = MessageDigest.getInstance("SHA-1")
            digest.update(passwordBytes)
            digest.update("Mighty Aphrodite".toByteArray(Charsets.UTF_8))
            digest.update(body)
            require(MessageDigest.isEqual(digest.digest(), expectedDigest)) {
                "JKS password verification failed"
            }

            return parseBody(body, alias, passwordBytes)
        } finally {
            expectedDigest.fill(0)
            body.fill(0)
            bytes.fill(0)
            passwordBytes.fill(0)
        }
    }

    private fun parseBody(body: ByteArray, requestedAlias: String, passwordBytes: ByteArray): Result {
        val input = DataInputStream(ByteArrayInputStream(body))
        require(input.readInt() == MAGIC) { "Invalid JKS magic" }
        val version = input.readInt()
        require(version == VERSION_1 || version == VERSION_2) { "Unsupported JKS version $version" }
        val count = input.readInt()
        require(count in 0..10_000) { "Invalid JKS entry count" }

        var found: Result? = null
        repeat(count) {
            when (input.readInt()) {
                PRIVATE_KEY_ENTRY -> {
                    val actualAlias = input.readUTF()
                    input.readLong()
                    val encryptedKey = readBytes(input)
                    val chainCount = input.readInt()
                    require(chainCount in 0..100) { "Invalid JKS certificate count" }
                    val chain = ArrayList<X509Certificate>(chainCount)
                    repeat(chainCount) {
                        val type = if (version == VERSION_2) input.readUTF() else "X.509"
                        val certBytes = readBytes(input)
                        val factory = CertificateFactory.getInstance(type)
                        val cert = factory.generateCertificate(
                            ByteArrayInputStream(certBytes)
                        ) as? X509Certificate
                            ?: error("JKS certificate is not X.509")
                        chain += cert
                    }
                    if (actualAlias.equals(requestedAlias, ignoreCase = true)) {
                        require(chain.isNotEmpty()) { "JKS alias has no certificate chain" }
                        val key = decryptPrivateKey(encryptedKey, passwordBytes)
                        found = Result(actualAlias, key, chain)
                    }
                }

                TRUSTED_CERT_ENTRY -> {
                    input.readUTF()
                    input.readLong()
                    if (version == VERSION_2) input.readUTF()
                    readBytes(input)
                }

                else -> error("Unrecognized JKS entry")
            }
        }
        require(input.available() == 0) { "Trailing data in JKS file" }
        return found ?: error("JKS alias '$requestedAlias' not found")
    }

    private fun readBytes(input: DataInputStream): ByteArray {
        val length = input.readInt()
        require(length in 0..MAX_ENTRY_BYTES) { "Invalid JKS entry length" }
        return ByteArray(length).also { input.readFully(it) }
    }

    private fun decryptPrivateKey(encryptedInfoBytes: ByteArray, passwordBytes: ByteArray): PrivateKey {
        val encryptedInfo = EncryptedPrivateKeyInfo.getInstance(encryptedInfoBytes)
        require(encryptedInfo.encryptionAlgorithm.algorithm.id == KEY_PROTECTOR_OID) {
            "Unsupported JKS private-key protection algorithm"
        }
        val protectedKey = encryptedInfo.encryptedData
        require(protectedKey.size > DIGEST_SIZE * 2) { "Invalid encrypted JKS private key" }

        val salt = protectedKey.copyOfRange(0, DIGEST_SIZE)
        val encryptedLength = protectedKey.size - DIGEST_SIZE * 2
        val encryptedKey = protectedKey.copyOfRange(DIGEST_SIZE, DIGEST_SIZE + encryptedLength)
        val expectedChecksum = protectedKey.copyOfRange(
            DIGEST_SIZE + encryptedLength, protectedKey.size
        )
        val xorKey = ByteArray(encryptedLength)
        val plainKey = ByteArray(encryptedLength)
        try {
            val sha1 = MessageDigest.getInstance("SHA-1")
            var previous = salt
            var offset = 0
            while (offset < xorKey.size) {
                sha1.update(passwordBytes)
                sha1.update(previous)
                previous = sha1.digest()
                val copyLength = minOf(previous.size, xorKey.size - offset)
                previous.copyInto(xorKey, offset, 0, copyLength)
                offset += copyLength
            }

            for (i in plainKey.indices) {
                plainKey[i] =
                    (encryptedKey[i].toInt() xor xorKey[i].toInt()).toByte()
            }
            sha1.reset()
            sha1.update(passwordBytes)
            sha1.update(plainKey)
            require(MessageDigest.isEqual(sha1.digest(), expectedChecksum)) {
                "JKS private-key password verification failed"
            }

            val keyInfo = PrivateKeyInfo.getInstance(plainKey)
            val keyAlgorithm = when (keyInfo.privateKeyAlgorithm.algorithm.id) {
                "1.2.840.113549.1.1.1" -> "RSA"
                "1.2.840.10045.2.1" -> "EC"
                "1.2.840.10040.4.1" -> "DSA"
                else -> error("Unsupported JKS private-key algorithm")
            }
            return KeyFactory.getInstance(keyAlgorithm)
                .generatePrivate(PKCS8EncodedKeySpec(plainKey))
        } finally {
            salt.fill(0)
            encryptedKey.fill(0)
            expectedChecksum.fill(0)
            xorKey.fill(0)
            plainKey.fill(0)
            protectedKey.fill(0)
            encryptedInfoBytes.fill(0)
        }
    }

    private fun passwordBytes(password: CharArray): ByteArray {
        val result = ByteArray(password.size * 2)
        for (i in password.indices) {
            result[i * 2] = (password[i].code ushr 8).toByte()
            result[i * 2 + 1] = password[i].code.toByte()
        }
        return result
    }
}
