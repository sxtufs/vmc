package com.vmp.packer

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.util.zip.CRC32
import java.util.zip.Deflater
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Rebuilds the input APK with rewritten dex files, a patched manifest, the
 * authenticated VMPC asset, and ABI-specific libVMP entries. Existing ZIP
 * entries are streamed through; rewritten entries are emitted explicitly.
 */
object ApkBuilder {

    fun build(
        input: File,
        output: File,
        newDexes: List<ByteArray>,
        dexNames: List<String>,
        newManifest: ByteArray,
        vmcs: List<ByteArray>,
        libVmpEntries: List<LibEntry>,
        extractNativeLibs: Boolean,
        /** Shipped as lib<name>.so; must match the SONAME rewritten in the .so. */
        libName: String,
        /** Slash-form loader class name (exactly 12 bytes, e.g.
         *  "com/an6v7/v3"); must match the class DexRewriter injected. */
        loaderClassSlash: String,
        /** 32-byte SHA-256 of the signing certificate. Baked into
         *  g_keySlot+80 and folded into the container key (appKey ^ certPin);
         *  all-zero = no pin and no fold. */
        certPin: ByteArray,
        /** Container asset name inside the output APK (no "assets/" prefix). */
        assetName: String,
        /** The vmp.abi.N ceiling VmcWriter was built with. Must match: it picks
         *  single- vs multi-LUT un-permutation, and the wrong table layout decodes
         *  every opcode wrong. The envelope version ladder itself is derived from
         *  the sections present, not from this. */
        runtimeCap: Int,
        onLog: (String) -> Unit
    ) {
        require(dexNames.size == newDexes.size) { "dex names/count mismatch" }
        require(vmcs.size == newDexes.size) { "vmc count mismatch" }

        val replacedDexNames = dexNames.toHashSet()

        val appKey = ByteArray(32)
        java.security.SecureRandom().nextBytes(appKey)
        val patchedLibs = libVmpEntries.map { e ->
            val b = e.bytes.copyOf()
            patchLoaderClassName(b, loaderClassSlash, e.abi)
            patchKeySlot(b, appKey, certPin, e.abi)
            patchAssetName(b, assetName, e.abi)
            patchSoname(b, libName, e.abi)
            stripAbiToken(b)
            LibEntry(e.abi, b)
        }

        var copied = 0
        var skipped = 0
        var libCopied = 0
        val seenNames = HashSet<String>()

        ZipInputStream(input.inputStream().buffered()).use { zis ->
            val rawOut = FileOutputStream(output)
            var pos = 0L
            val fileChannel = rawOut.channel
            ZipOutputStream(rawOut).use { zos ->
                var entry = zis.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (!seenNames.add(name))
                        error("Input APK contains duplicate ZIP entry '$name'")
                    val isV1Sig = name.startsWith("META-INF/") && (
                        name.endsWith(".MF") || name.endsWith(".SF") ||
                        name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")
                    )
                    if (isV1Sig || name in replacedDexNames) {
                        skipped++
                    } else if (name == "AndroidManifest.xml") {
                        zos.putNextEntry(ZipEntry(name))
                        zos.write(newManifest)
                        zos.closeEntry()
                        pos = fileChannel.position()
                        copied++
                    } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                        val libBytes = ApkUtil.readLimited(zis, MAX_ZIP_ENTRY_BYTES)
                        if (extractNativeLibs) {
                            if (entry.method == ZipEntry.STORED) {
                                pos = writeStoredAligned(zos, fileChannel, onLog, pos, name, libBytes, 16)
                            } else {
                                val ze = ZipEntry(name)
                                zos.putNextEntry(ze)
                                zos.write(libBytes)
                                zos.closeEntry()
                                pos = fileChannel.position()
                            }
                        } else {
                            pos = writeStoredAligned(zos, fileChannel, onLog, pos, name, libBytes, 16384)
                        }
                        libCopied++
                        copied++
                    } else {
                        if (entry.method == ZipEntry.STORED) {
                            val data = ApkUtil.readLimited(zis, MAX_ZIP_ENTRY_BYTES)
                            pos = writeStoredAligned(zos, fileChannel, onLog, pos, name, data, 4)
                        } else {
                            zos.putNextEntry(ZipEntry(name))
                            ApkUtil.copyLimited(zis, zos, MAX_ZIP_ENTRY_BYTES)
                            zos.closeEntry()
                            pos = fileChannel.position()
                        }
                        copied++
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
                for (i in newDexes.indices) {
                    zos.putNextEntry(ZipEntry(dexNames[i]))
                    zos.write(newDexes[i])
                    zos.closeEntry()
                    pos = fileChannel.position()
                }
                if (vmcs.isNotEmpty()) {
                    val containerKey =
                        if (certPin.all { it == 0.toByte() }) appKey
                        else ByteArray(32) { (appKey[it].toInt() xor certPin[it].toInt()).toByte() }
                    val container = buildContainer(vmcs, containerKey, runtimeCap)
                    pos = writeStoredAligned(zos, fileChannel, onLog, pos,
                            "assets/$assetName", container, 1)
                }
                for (entry in patchedLibs) {
                    val libPath = "lib/${entry.abi}/lib$libName.so"
                    if (extractNativeLibs) {
                        val ze = ZipEntry(libPath)
                        zos.putNextEntry(ze)
                        zos.write(entry.bytes)
                        zos.closeEntry()
                        pos = fileChannel.position()
                    } else {
                        pos = writeStoredAligned(zos, fileChannel, onLog, pos,
                                libPath, entry.bytes, 16384)
                    }
                }
            }
        }
        if (output.length() > MAX_APK_BYTES) {
            output.delete()
            error("Unsigned output exceeds the ${MAX_APK_BYTES}-byte runtime verification limit")
        }
        onLog("Copied $copied entries ($libCopied lib .so), " +
                "skipped $skipped (META-INF + original dexes)")
        onLog("Emitted ${newDexes.size} dexes, " +
                "1 VMC container (${vmcs.size} dex blob(s)), " +
                "${libVmpEntries.size} native libs")
        onLog("Unsigned APK: ${output.absolutePath} (${output.length()} bytes)")
    }

    /** Builds the VMPC v4 envelope consumed by the native runtime. Each VMP2
     * blob is compressed, ChaCha20-transformed, and accompanied by an HMAC tag
     * over its index, sizes, CRC, and ciphertext.
     */
    private fun buildContainer(vmcs: List<ByteArray>, key: ByteArray,
                               runtimeCap: Int): ByteArray {
        val headerSize = 12 + 48 * vmcs.size
        val cap = runtimeCap
        val insnKey = deriveInsnKey(key)
        val blobs = ArrayList<ByteArray>(vmcs.size)
        for (blob in vmcs) {
            var b = blob
            var permuted = 0
            val rawVersion = le32(b, 4)
            if (rawVersion > 2)
                error("VMC blob already carries a protection version ($rawVersion)")
            if (le32(b, InsnPerm.PERM_OFF_SLOT) >= 112) {
                if (rawVersion != 2)
                    error("perm section on a non-bumpable blob (version $rawVersion)")
                val cand = b.copyOf()
                val multi = cap >= InsnPerm.MULTI_PERM_CAP
                if (!InsnPerm.applyToBlob(cand, s2c = false, multi = multi))
                    error("perm section present but applyToBlob refused the blob - " +
                            "inconsistent container, refusing to ship")
                b = cand; permuted = if (multi) 2 else 1
            }
            if (le32(b, IrCodec.IR_OFF_SLOT) != 0 && permuted != 2)
                error("IR section present without multi-LUT permute - refusing to ship")
            if (cap >= 3 && rawVersion == 2) b = encryptMethodInsns(b, insnKey, permuted)
            blobs.add(b)
        }
        val payloads = ArrayList<ByteArray>(blobs.size)
        val tags = ArrayList<ByteArray>(blobs.size)
        val authKey = deriveAuthKey(key)
        var total = headerSize
        for ((i, blob) in blobs.withIndex()) {
            val p = chacha20Transform(deflateBytes(blob), i, key)
            payloads.add(p)
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(authKey, "HmacSHA256"))
            val auth = ByteArray(16 + p.size)
            putLe32(auth, 0, i)
            putLe32(auth, 4, p.size)
            putLe32(auth, 8, blob.size)
            val crc = CRC32()
            crc.update(blob)
            putLe32(auth, 12, crc.value.toInt())
            System.arraycopy(p, 0, auth, 16, p.size)
            tags.add(mac.doFinal(auth))
            total += p.size
        }
        val buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        buf.put("VMPC".toByteArray(Charsets.US_ASCII))
        buf.putInt(4)
        buf.putInt(blobs.size)
        var off = headerSize
        for (i in blobs.indices) {
            val crc = CRC32()
            crc.update(blobs[i])
            buf.putInt(off)
            buf.putInt(payloads[i].size)
            buf.putInt(blobs[i].size)
            buf.putInt(crc.value.toInt())
            buf.put(tags[i])
            off += payloads[i].size
        }
        for (p in payloads) buf.put(p)
        return buf.array()
    }

    /** XOR [len] bytes of [buf] at [start] with a ChaCha20 keystream (counter from 0). */
    internal fun chacha20StreamXor(buf: ByteArray, start: Int, len: Int,
                                   key: ByteArray, nonce: ByteArray) {
        val block = ByteArray(64)
        var off = 0
        var counter = 0
        while (off < len) {
            chacha20Block(key, counter, nonce, block)
            val n = minOf(64, len - off)
            var j = 0
            while (j < n) {
                buf[start + off + j] = ((buf[start + off + j].toInt() and 0xFF) xor
                        (block[j].toInt() and 0xFF)).toByte()
                j++
            }
            off += n
            counter++
        }
    }

    private fun le16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)

    /**
     * Second ChaCha20 layer over a VMP2 blob's instruction ranges, nonce
     * "DATA"||insns_off (VmpFile::getInsns reverses it), so an idle dump sees
     * ciphertext. Blob version after this call: 3 = encrypted, 4 = + single-LUT
     * permute, 5 = + multi-LUT permute, 6 = + IR records.
     */
    private fun encryptMethodInsns(blob: ByteArray, key: ByteArray, permuted: Int): ByteArray {
        val out = blob.copyOf()
        val codeSize = le32(out, 68)
        val codeOff = le32(out, 72)
        val dataOff = le32(out, 80)
        val count = codeSize / 36
        val irOff = le32(out, 96)
        val nonce = ByteArray(12)
        nonce[0] = 0x44; nonce[1] = 0x41; nonce[2] = 0x54; nonce[3] = 0x41
        var anyIr = false
        for (i in 0 until count) {
            val base = codeOff + i * 36
            val insnsSize = le32(out, base + 20)
            val insnsOff = le32(out, base + 24)
            val start = dataOff + insnsOff
            var len = insnsSize * 2
            if (le32(out, base + 4) and IrCodec.IR_ACCESS_BIT != 0) {
                val tab = le32(out, irOff + 4 + 4 * i)
                len = le16(out, irOff + tab) * 16
                anyIr = true
            }
            if (start < 0 || len < 0 || len > out.size - start)
                error("VMC record $i: insns range $start..${start + len} " +
                        "outside the ${out.size}-byte blob - corrupt code table")
            nonce[4] = (insnsOff and 0xff).toByte()
            nonce[5] = ((insnsOff ushr 8) and 0xff).toByte()
            nonce[6] = ((insnsOff ushr 16) and 0xff).toByte()
            nonce[7] = ((insnsOff ushr 24) and 0xff).toByte()
            chacha20StreamXor(out, start, len, key, nonce)
        }
        out[4] = (if (anyIr && permuted == 2) 6 else permuted + 3).toByte()
        out[5] = 0; out[6] = 0; out[7] = 0
        return out
    }

    private fun putLe32(dst: ByteArray, off: Int, value: Int) {
        dst[off] = value.toByte()
        dst[off + 1] = (value ushr 8).toByte()
        dst[off + 2] = (value ushr 16).toByte()
        dst[off + 3] = (value ushr 24).toByte()
    }

    private fun deflateBytes(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        val out = ByteArrayOutputStream(data.size / 2 + 64)
        val window = ByteArray(8192)
        deflater.setInput(data)
        deflater.finish()
        while (!deflater.finished()) {
            val n = deflater.deflate(window)
            if (n > 0) out.write(window, 0, n)
        }
        deflater.end()
        return out.toByteArray()
    }

    /**
     * ChaCha20 (RFC 8439). MUST stay byte-for-byte in sync with
     * vmp_chacha20_block()/vmpChaChaTransform() in native/src/vmp.cpp; both sides
     * are pinned to the RFC 8439 2.3.2 vector by unit tests. The nonce carries the
     * blob index, so blobs of one container never share keystream.
     */
    internal fun chacha20Transform(src: ByteArray, blobIndex: Int, key: ByteArray): ByteArray {
        val out = ByteArray(src.size)
        val nonce = ByteArray(12)
        nonce[0] = blobIndex.toByte()
        nonce[1] = (blobIndex ushr 8).toByte()
        nonce[2] = (blobIndex ushr 16).toByte()
        nonce[3] = (blobIndex ushr 24).toByte()
        val block = ByteArray(64)
        var off = 0
        var counter = 0
        while (off < src.size) {
            chacha20Block(key, counter, nonce, block)
            val n = minOf(64, src.size - off)
            for (j in 0 until n)
                out[off + j] = ((src[off + j].toInt() and 0xFF) xor
                        (block[j].toInt() and 0xFF)).toByte()
            off += n
            counter++
        }
        return out
    }

    /** Mirror of the runtime vmpDeriveInsnKey (vmp.cpp); fixed counter/nonce give domain separation. */
    internal fun deriveInsnKey(envKey: ByteArray): ByteArray {
        val nonce = byteArrayOf(0x56, 0x4D, 0x50, 0x4B, 0x30, 0x4B,
                                0x44, 0x46, 0x49, 0x4E, 0x53, 0x4E)
        val block = ByteArray(64)
        chacha20Block(envKey, 0x2E17A3C1, nonce, block)
        return block.copyOfRange(0, 32)
    }

    /** Mirror of the runtime vmpDeriveAuthKey (vmp.cpp); its own ChaCha20 block gives HMAC-key domain separation. */
    internal fun deriveAuthKey(envKey: ByteArray): ByteArray {
        val nonce = byteArrayOf(0x56, 0x4D, 0x50, 0x43, 0x30, 0x4B,
                                0x41, 0x55, 0x54, 0x48, 0x56, 0x34)
        val block = ByteArray(64)
        chacha20Block(envKey, 0x2E17A3C2, nonce, block)
        return block.copyOfRange(0, 32)
    }

    /** One ChaCha20 block: 64 keystream bytes from key(32)+counter+nonce(12). */
    internal fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray,
                               out: ByteArray) {
        val s = IntArray(16)
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
        for (i in 0 until 8) s[4 + i] = le32(key, 4 * i)
        s[12] = counter
        for (i in 0 until 3) s[13 + i] = le32(nonce, 4 * i)
        val x = s.copyOf()
        for (r in 0 until 10) {
            qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13)
            qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
            qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12)
            qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
        }
        for (i in 0 until 16) {
            val v = x[i] + s[i]
            out[4 * i] = v.toByte()
            out[4 * i + 1] = (v ushr 8).toByte()
            out[4 * i + 2] = (v ushr 16).toByte()
            out[4 * i + 3] = (v ushr 24).toByte()
        }
    }

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }

    private fun rotl(v: Int, c: Int): Int = (v shl c) or (v ushr (32 - c))

    private fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
                ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

    private val TEMPLATE_KEY_SLOT_MAGIC = byteArrayOf(
        0x5E, 0xA2.toByte(), 0x17, 0xCB.toByte(), 0x84.toByte(), 0x39, 0xF1.toByte(), 0x6D,
        0xB0.toByte(), 0x25, 0x9E.toByte(), 0x48, 0xDA.toByte(), 0x73, 0x0C, 0xEF.toByte()
    )

    /** Write fresh magic, build-const, and key XOR const into the slot. */
    private fun patchKeySlot(so: ByteArray, key: ByteArray, certPin: ByteArray, abi: String) {
        require(certPin.size == 32) { "cert pin must be a SHA-256 (32 bytes), got ${certPin.size}" }
        val at = indexOfSeq(so, TEMPLATE_KEY_SLOT_MAGIC)
        if (at < 0)
            error("libVMP ($abi) has no key-slot marker - rebuild the .so from the patched native source before packing")
        if (indexOfSeq(so, TEMPLATE_KEY_SLOT_MAGIC, at + 1) >= 0)
            error("libVMP ($abi) has multiple key-slot markers - ambiguous, refusing")
        if (at + 112 > so.size)
            error("libVMP ($abi) 112-byte key-slot runs past the end of the image")
        val rnd = java.security.SecureRandom()
        val newMagic = ByteArray(16).also { rnd.nextBytes(it) }
        val newConst = ByteArray(32).also { rnd.nextBytes(it) }
        for (i in 0 until 16) so[at + i] = newMagic[i]
        for (i in 0 until 32) so[at + 16 + i] = newConst[i]
        for (i in 0 until 32)
            so[at + 48 + i] = ((key[i].toInt() and 0xFF) xor (newConst[i].toInt() and 0xFF)).toByte()
        for (i in 0 until 32) so[at + 80 + i] = certPin[i]
    }

    /** Asset-name literal, rewritten per output. The source string must stay exactly
     *  "VMC.payload"; the leading NUL keeps log literals from
     *  matching by suffix. */
    private val ASSET_NAME_TEMPLATE = byteArrayOf(
        0,
        'V'.code.toByte(), 'M'.code.toByte(), 'C'.code.toByte(), '.'.code.toByte(),
        'p'.code.toByte(), 'a'.code.toByte(), 'y'.code.toByte(), 'l'.code.toByte(),
        'o'.code.toByte(), 'a'.code.toByte(), 'd'.code.toByte(), 0
    )

    private fun patchAssetName(so: ByteArray, assetName: String, abi: String) {
        val name = assetName.toByteArray(Charsets.US_ASCII)
        val capacity = ASSET_NAME_TEMPLATE.size - 2
        if (name.isEmpty() || name.size + 1 > capacity)
            error("container asset name '$assetName' does not fit the ${capacity - 1}-char template")
        val at = indexOfSeq(so, ASSET_NAME_TEMPLATE)
        if (at < 0)
            error("libVMP ($abi) has no container asset-name literal - rebuild the .so from the patched native source before packing")
        if (indexOfSeq(so, ASSET_NAME_TEMPLATE, at + 1) >= 0)
            error("libVMP ($abi) asset-name template appears twice - ambiguous, refusing")
        val start = at + 1
        for (i in name.indices) so[start + i] = name[i]
        so[start + name.size] = 0
    }

    /** SONAME compiled into the shipped .so (CMake target "VMP"), rewritten to the
     *  output's own equal-length file name. */
    private val SONAME_TEMPLATE = byteArrayOf(
        'l'.code.toByte(), 'i'.code.toByte(), 'b'.code.toByte(), 'V'.code.toByte(),
        'M'.code.toByte(), 'P'.code.toByte(), '.'.code.toByte(), 's'.code.toByte(),
        'o'.code.toByte(), 0
    )

    /** Capability token in .rodata, stripped per output so `strings` cannot name the
     *  container generation. Silent when absent, so older templates still pack. */
    private val ABI_TOKEN_PREFIX = "vmp.abi.".toByteArray(Charsets.US_ASCII)

    private fun stripAbiToken(so: ByteArray) {
        var at = indexOfSeq(so, ABI_TOKEN_PREFIX)
        while (at >= 0) {
            var n = 0
            while (at + n < so.size && so[at + n] != 0.toByte()) n++
            for (i in 0 until n) so[at + i] = 0
            at = indexOfSeq(so, ABI_TOKEN_PREFIX, at + 1)
        }
    }

    private fun patchSoname(so: ByteArray, libName: String, abi: String) {
        val name = "lib$libName.so".toByteArray(Charsets.US_ASCII)
        if (name.size + 1 != SONAME_TEMPLATE.size)
            error("lib name '$libName' must be ${SONAME_TEMPLATE.size - 7} chars to match the SONAME anchor")
        val at = indexOfSeq(so, SONAME_TEMPLATE)
        if (at < 0)
            error("libVMP ($abi) has no SONAME anchor - built from a renamed CMake target? rebuild before packing")
        if (indexOfSeq(so, SONAME_TEMPLATE, at + 1) >= 0)
            error("libVMP ($abi) SONAME anchor appears twice - ambiguous, refusing")
        for (i in name.indices) so[at + i] = name[i]
        so[at + name.size] = 0
    }

    /** Loader-class literal in the template .so, rewritten per output. Plain .rodata,
     *  NOT .dynstr: renaming an exported symbol in place leaves the ELF hash tables
     *  stale. The leading NUL is part of the anchor; appears EXACTLY once. */
    private val LOADER_CLASS_TEMPLATE = byteArrayOf(
        0,
        'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), '/'.code.toByte(),
        'e'.code.toByte(), 'r'.code.toByte(), 'r'.code.toByte(), 'o'.code.toByte(),
        'r'.code.toByte(), '/'.code.toByte(), 'v'.code.toByte(), 'm'.code.toByte(),
        0
    )

    private fun patchLoaderClassName(so: ByteArray, loaderClassSlash: String, abi: String) {
        val name = loaderClassSlash.toByteArray(Charsets.US_ASCII)
        if (name.size != 12)
            error("loader class '$loaderClassSlash' must be 12 bytes (com/<5>/<2>) to fit the kLoaderClass slot")
        val at = indexOfSeq(so, LOADER_CLASS_TEMPLATE)
        if (at < 0)
            error("libVMP ($abi) has no loader-class literal - rebuild the .so from the patched native source before packing")
        if (indexOfSeq(so, LOADER_CLASS_TEMPLATE, at + 1) >= 0)
            error("libVMP ($abi) loader-class literal appears twice - ambiguous, refusing")
        val start = at + 1
        for (i in name.indices) so[start + i] = name[i]
    }

    private fun indexOfSeq(hay: ByteArray, needle: ByteArray, from: Int = 0): Int {
        var i = from
        val last = hay.size - needle.size
        while (i <= last) {
            var j = 0
            while (j < needle.size && hay[i + j] == needle[j]) j++
            if (j == needle.size) return i
            i++
        }
        return -1
    }

    /** Write a STORED ZIP entry whose payload starts on [alignment]. */
    private fun writeStoredAligned(
        zos: ZipOutputStream,
        channel: FileChannel,
        onLog: (String) -> Unit,
        currentPos: Long,
        name: String,
        data: ByteArray,
        alignment: Int
    ): Long {
        val crc = CRC32()
        crc.update(data)
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val headerBeforeData = currentPos + 30 + nameBytes.size
        val pad = ((alignment - (headerBeforeData % alignment)) % alignment).toInt()
        val extraLen = when {
            pad == 0 -> 0
            pad < 4 -> alignment + pad
            else -> pad
        }
        val entry = ZipEntry(name)
        entry.method = ZipEntry.STORED
        entry.size = data.size.toLong()
        entry.compressedSize = data.size.toLong()
        entry.crc = crc.value
        if (extraLen > 0) {
            val extra = ByteArray(extraLen)
            extra[0] = 0xFF.toByte()
            extra[1] = 0xFF.toByte()
            val payloadLen = extraLen - 4
            extra[2] = (payloadLen and 0xff).toByte()
            extra[3] = ((payloadLen ushr 8) and 0xff).toByte()
            entry.extra = extra
        }
        zos.putNextEntry(entry)
        zos.write(data)
        zos.closeEntry()
        val actual = channel.position()
        val expected = currentPos + 30 + nameBytes.size + extraLen + data.size
        if (actual != expected)
            onLog("  WARNING: stored entry '$name' ended at $actual, arithmetic said " +
                    "$expected - later entries are re-aligned from the real position, " +
                    "but the encoder is writing something this function does not model")
        return actual
    }
}

data class LibEntry(val abi: String, val bytes: ByteArray)