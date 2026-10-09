package com.vmp.packer

import android.content.Context
import android.net.Uri
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest

/** Stores one imported JKS and non-secret display metadata. */
object JksProfileStore {
    private const val PREFS = "vmp_custom_jks"
    private const val KEY_NAME = "name"
    private const val KEY_ALIAS = "alias"
    private const val KEY_CERT_SHA256 = "certSha256"
    private const val KEY_SUBJECT = "subject"
    private const val KEY_PASSWORD = "passwordCiphertext"
    private const val PASSWORD_SECRET_ALIAS = "vmp_custom_jks_password"
    private const val FILE_NAME = "custom.jks"
    private const val TEMP_NAME = "custom.jks.tmp"
    private const val BACKUP_NAME = "custom.jks.old"
    private const val MAX_JKS_BYTES = 8L * 1024L * 1024L

    data class Profile(
        val name: String,
        val alias: String,
        val certSha256: String,
        val subject: String,
        val file: File
    )

    fun load(context: Context): Profile? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val name = prefs.getString(KEY_NAME, null)?.takeIf { it.isNotBlank() } ?: return null
        val alias = prefs.getString(KEY_ALIAS, null)?.takeIf { it.isNotBlank() } ?: return null
        val certSha256 = prefs.getString(KEY_CERT_SHA256, null)?.takeIf { it.isNotBlank() } ?: return null
        val subject = prefs.getString(KEY_SUBJECT, "") ?: ""
        val file = File(context.filesDir, FILE_NAME)
        return if (file.isFile) Profile(name, alias, certSha256, subject, file) else null
    }

    fun importJks(
        context: Context,
        uri: Uri,
        name: String,
        alias: String,
        password: CharArray
    ): Profile {
        val cleanName = name.trim().replace(Regex("[\\r\\n]"), " ")
        val cleanAlias = alias.trim().replace(Regex("[\\r\\n]"), " ")
        require(cleanName.isNotEmpty()) { "Keystore name is required" }
        require(cleanAlias.isNotEmpty()) { "Keystore alias is required" }

        val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
            ApkUtil.readLimited(input, MAX_JKS_BYTES)
        } ?: error("Cannot open JKS file")

        val signer = ApkSigner.loadJksSigner(
            ByteArrayInputStream(bytes), cleanAlias, password
        )
        val cert = signer.certChain.firstOrNull()
            ?: error("JKS alias has no certificate")
        val certSha256 = sha256Hex(cert.encoded)
        val subject = cert.subjectX500Principal.name
        val encryptedPassword = SecretStore.encrypt(PASSWORD_SECRET_ALIAS, password)

        val dir = context.filesDir
        val temp = File(dir, TEMP_NAME)
        val backup = File(dir, BACKUP_NAME)
        val destination = File(dir, FILE_NAME)
        FileOutputStream(temp).use { it.write(bytes) }
        backup.delete()
        if (destination.exists() && !destination.renameTo(backup)) {
            temp.delete()
            error("Cannot replace the existing JKS")
        }
        if (!temp.renameTo(destination)) {
            temp.delete()
            backup.renameTo(destination)
            error("Cannot store the imported JKS")
        }
        backup.delete()

        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_NAME, cleanName)
            .putString(KEY_ALIAS, cleanAlias)
            .putString(KEY_CERT_SHA256, certSha256)
            .putString(KEY_SUBJECT, subject)
            .putString(KEY_PASSWORD, encryptedPassword)
            .apply()

        return Profile(cleanName, cleanAlias, certSha256, subject, destination)
    }

    fun loadPassword(context: Context): CharArray? {
        val encoded = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_PASSWORD, null) ?: return null
        return try {
            SecretStore.decrypt(PASSWORD_SECRET_ALIAS, encoded)
        } catch (_: Exception) {
            null
        }
    }

    fun rememberPassword(context: Context, password: CharArray) {
        val encrypted = SecretStore.encrypt(PASSWORD_SECRET_ALIAS, password)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_PASSWORD, encrypted)
            .apply()
    }

    fun validatePassword(profile: Profile, password: CharArray) {
        FileInputStream(profile.file).use {
            ApkSigner.loadJksSigner(it, profile.alias, password)
        }
    }

    fun remove(context: Context) {
        File(context.filesDir, FILE_NAME).delete()
        File(context.filesDir, TEMP_NAME).delete()
        File(context.filesDir, BACKUP_NAME).delete()
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().clear().apply()
        SecretStore.delete(PASSWORD_SECRET_ALIAS)
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
