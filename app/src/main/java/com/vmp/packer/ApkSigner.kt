package com.vmp.packer

import android.content.Context
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * Resolves the signing identity used for one pack. Nonblank identity tags use a
 * persistent PKCS#12 identity under `filesDir/vmp_ids`; a blank tag creates a
 * fresh in-memory RSA identity. Packer resolves the identity once so the
 * certificate pin and the signing key always refer to the same certificate.
 */
object ApkSigner {

  private const val IDS_DIR = "vmp_ids"
  private const val PREFS = "vmp_signer"
  private const val GENERATED_PASSWORD_PREFIX = "vmp_generated_jks_"
  private const val ENCRYPTED_PASSWORD_PREFIX = "v1:"

  init {
    try {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    } catch (_: Exception) {
    }
    try {
      Security.insertProviderAt(BouncyCastleProvider(), 1)
    } catch (_: Exception) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  /** One resolved signing identity. certDer is what the pin hashes. */
  data class Signer(
      val alias: String,
      val privateKey: PrivateKey,
      val certChain: List<X509Certificate>
  ) {
    val certDer: ByteArray get() = certChain[0].encoded
  }

  /** Load and validate one private-key entry from a JKS keystore. */
  fun loadJksSigner(input: InputStream, alias: String, password: CharArray): Signer {
    val loaded = JksReader.load(input, alias, password)
    return Signer(loaded.alias, loaded.privateKey, loaded.certificateChain)
  }

  @Synchronized
  fun resolveSigner(ctx: Context, source: SigningSource): Signer = when (source) {
    is SigningSource.Generated -> resolveSigner(ctx, source.identityTag)
    is SigningSource.ImportedJks -> {
      try {
        FileInputStream(source.file).use {
          loadJksSigner(it, source.alias, source.password)
        }
      } finally {
        source.clearPassword()
      }
    }
  }

  @Synchronized
  fun resolveSigner(ctx: Context, identityTag: String?): Signer {
    val tag = identityTag?.trim()?.takeIf { it.isNotEmpty() }

    if (tag == null) {
      val kp = newKeyPair()
      val serial = BigInteger(128, SecureRandom()).let {
        if (it.signum() == 0) BigInteger.ONE else it
      }
      val cert = newSelfSignedCert(
          kp, "CN=" + randomHex(8), serial, System.currentTimeMillis())
      return Signer("k", kp.private, listOf(cert))
    }

    val idHash = sha256Hex(tag)
    val dir = File(ctx.filesDir, IDS_DIR).apply { mkdirs() }
    val file = File(dir, "$idHash.p12")
    val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val storedPassword = prefs.getString("pw_" + idHash, null)
    val alias = prefs.getString("al_" + idHash, null)
    if (storedPassword == null || alias == null || !file.exists()) {
      file.delete()
      SecretStore.delete(generatedPasswordAlias(idHash))
      val newPw = randomSecret(24).toCharArray()
      val newAlias = "k" + randomSecret(8)
      try {
        val kp = newKeyPair()
        val cn = "CN=" + tag.removePrefix("auto:")
            .replace(Regex("[\"'=+,;<>\\\\/]"), "_")
        val cert = newSelfSignedCert(
            kp, cn, BigInteger.valueOf(System.currentTimeMillis()),
            System.currentTimeMillis())
        KeyStore.getInstance("PKCS12").apply {
          load(null, newPw)
          setKeyEntry(newAlias, kp.private, newPw, arrayOf(cert))
          FileOutputStream(file).use { store(it, newPw) }
        }
        prefs.edit().putString("pw_" + idHash,
            encryptGeneratedPassword(ctx, idHash, newPw))
            .putString("al_" + idHash, newAlias).apply()
        return Signer(newAlias, kp.private, listOf(cert))
      } finally {
        newPw.fill('\u0000')
      }
    }

    val pw = loadGeneratedPassword(ctx, idHash, storedPassword, prefs)
    try {
      val ks = KeyStore.getInstance("PKCS12").apply {
        FileInputStream(file).use { input ->
          load(input, pw)
        }
      }
      val key = ks.getKey(alias, pw) as? PrivateKey
          ?: error("named identity '$tag': no private key for alias $alias")
      val chain = ks.getCertificateChain(alias)
          ?: error("named identity '$tag': no certificate chain for alias $alias")
      return Signer(alias, key, chain.map { it as X509Certificate })
    } finally {
      pw.fill('\u0000')
    }
  }

  /** V1+V2+V3 over the resolved signer. V1 stays on: the signature pin reads
   *  GET_SIGNATURES, and named identities must install on old platforms. */
  fun sign(input: File, output: File, s: Signer) {
    val signerConfig = ApkSigner.SignerConfig.Builder(
      s.alias,
      s.privateKey,
      java.util.ArrayList(s.certChain)
    ).build()

    val signer = ApkSigner.Builder(
      listOf(signerConfig)
    )
    .setInputApk(input)
    .setOutputApk(output)
    .setV1SigningEnabled(true)
    .setV2SigningEnabled(true)
    .setV3SigningEnabled(true)
    .build()

    signer.sign()

    /* Use Google's verifier as the pack-time reference implementation. The
     * target APK still uses the native verifier at runtime because this
     * dependency is not injected into arbitrary protected APKs. */
    val verification = ApkVerifier.Builder(output).build().verify()
    if (!verification.isVerified)
      error("APK signature verification failed after signing")
  }

  private fun generatedPasswordAlias(idHash: String): String =
      GENERATED_PASSWORD_PREFIX + idHash

  private fun encryptGeneratedPassword(
      context: Context,
      idHash: String,
      password: CharArray
  ): String = ENCRYPTED_PASSWORD_PREFIX +
      SecretStore.encrypt(generatedPasswordAlias(idHash), password)

  private fun loadGeneratedPassword(
      context: Context,
      idHash: String,
      stored: String,
      prefs: android.content.SharedPreferences
  ): CharArray {
    if (stored.startsWith(ENCRYPTED_PASSWORD_PREFIX)) {
      return SecretStore.decrypt(
          generatedPasswordAlias(idHash),
          stored.removePrefix(ENCRYPTED_PASSWORD_PREFIX)
      )
    }

    val legacy = stored.toCharArray()
    try {
      prefs.edit().putString("pw_" + idHash,
          encryptGeneratedPassword(context, idHash, legacy)).apply()
      return legacy
    } catch (t: Exception) {
      legacy.fill('\u0000')
      throw t
    }
  }

  private fun newKeyPair(): KeyPair {
    val kpGen = KeyPairGenerator.getInstance("RSA")
    kpGen.initialize(2048, SecureRandom())
    return kpGen.generateKeyPair()
  }

  private fun newSelfSignedCert(
      kp: KeyPair, cn: String, serial: BigInteger, notBeforeMs: Long
  ): X509Certificate {
    val subject = X500Name(cn)
    val pubKeyInfo = SubjectPublicKeyInfo.getInstance(kp.public.encoded)
    val builder = X509v3CertificateBuilder(
        subject, serial,
        Date(notBeforeMs),
        Date(notBeforeMs + 10L * 365 * 24 * 3600 * 1000),
        subject, pubKeyInfo)
    builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
    val signer = JcaContentSignerBuilder("SHA256withRSA")
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(kp.private)
    return JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(builder.build(signer))
  }

  private fun randomSecret(len: Int): String {
    val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    val rnd = SecureRandom()
    return buildString { repeat(len) { append(alphabet[rnd.nextInt(alphabet.length)]) } }
  }

  private fun randomHex(len: Int): String {
    val b = ByteArray((len + 1) / 2)
    SecureRandom().nextBytes(b)
    return b.joinToString("") { "%02x".format(it) }.take(len)
  }

  private fun sha256Hex(s: String): String =
      MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
          .joinToString("") { "%02x".format(it) }
}
