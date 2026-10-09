package com.vmp.packer

/**
 * Reads whitelist anchors and selected application flags from binary
 * AndroidManifest.xml. Patching preserves the existing chunk/string-pool
 * structure and only changes existing string or typed-boolean values in place.
 */
object AxmlPatcher {

    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val FLAG_UTF8 = 0x00000100
    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_BOOLEAN = 0x12
    private const val MAX_STRING_COUNT = 1_000_000
    private const val ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"

    private fun validateStringPool(
        xml: ByteArray,
        fileSize: Int,
        poolStart: Int,
        poolSize: Int,
        headerSize: Int,
        stringCount: Int,
        stringsStart: Int
    ) {
        require(poolSize >= 28 &&
                poolStart.toLong() + poolSize.toLong() <= fileSize.toLong()) {
            "string pool lies outside the AXML file"
        }
        require(headerSize >= 28 && headerSize <= poolSize) {
            "invalid string-pool header size $headerSize"
        }
        require(stringCount in 0..MAX_STRING_COUNT) {
            "invalid string-pool count $stringCount"
        }
        require(headerSize.toLong() + stringCount.toLong() * 4L <= poolSize.toLong()) {
            "string offset table lies outside the string pool"
        }
        require(stringsStart >= headerSize + stringCount * 4 &&
                stringsStart.toLong() <= poolSize.toLong()) {
            "invalid string data offset $stringsStart"
        }
        require(poolStart >= 0 && poolStart <= xml.size) {
            "invalid string-pool offset $poolStart"
        }
    }

    /** Manifest element kinds that name an app component class. */
    private val COMPONENT_ELEMENT_NAMES =
        setOf("activity", "service", "receiver", "provider")

    /**
     * Component kinds the framework guarantees to be ContextWrapper subclasses -
     * the only ones that may receive an injected attachBaseContext(Context)V.
     * BroadcastReceiver/ContentProvider declare no attachBaseContext, so an
     * injected invoke-super against them fails class verification on ART.
     */
    private val CONTEXT_COMPONENT_ELEMENT_NAMES = setOf("activity", "service")

    /**
     * The whitelist anchors from the binary manifest: package, application
     * class, and component classes split by kind (see ManifestTargets).
     * Returns nulls for anything not present.
     */
    fun readTargets(xml: ByteArray): ManifestTargets {
        val fileSize = minOf(u32(xml, 4), xml.size)
        val poolStart = findChunk(xml, 8, fileSize, RES_STRING_POOL_TYPE)
        val poolSize = u32(xml, poolStart + 4)
        val headerSize = u16(xml, poolStart + 2)
        val stringCount = u32(xml, poolStart + 8)
        val flags = u32(xml, poolStart + 16)
        val stringsStart = u32(xml, poolStart + 20)
        val isUtf8 = (flags and FLAG_UTF8) != 0
        validateStringPool(xml, fileSize, poolStart, poolSize, headerSize,
                stringCount, stringsStart)

        val strings = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            val off = u32(xml, poolStart + headerSize + i * 4)
            require(off >= 0 && off.toLong() < poolSize.toLong() - stringsStart.toLong()) {
                "string offset $off lies outside the string data"
            }
            val sOff = poolStart + stringsStart + off
            strings.add(if (isUtf8) readUtf8(xml, sOff) else readUtf16(xml, sOff))
        }

        val androidNsIdx = strings.indexOf(ANDROID_NS_URI)


        var manifestPkg: String? = null
        var applicationClass: String? = null
        val componentClasses = ArrayList<String>()
        val contextComponentClasses = ArrayList<String>()
        var manifestFound = false
        var appFound = false

        var pos = poolStart + poolSize
        while (pos + 8 <= fileSize) {
            val type = u16(xml, pos)
            val size = u32(xml, pos + 4)
            if (size < 8) error("bad chunk size")
            if (type == RES_XML_START_ELEMENT_TYPE) {
                val elemName = strings.getOrNull(u32(xml, pos + 20))
                if (elemName == "manifest" && !manifestFound) {
                    manifestFound = true
                    manifestPkg = readStringAttr(xml, pos, size, "package", null, strings)
                } else if (elemName == "application" && !appFound) {
                    appFound = true
                    applicationClass = readStringAttr(
                        xml, pos, size, "name", androidNsIdx, strings)
                } else if (elemName != null && elemName in COMPONENT_ELEMENT_NAMES) {
                    val cn = readStringAttr(
                        xml, pos, size, "name", androidNsIdx, strings)
                    if (!cn.isNullOrEmpty()) {
                        componentClasses.add(cn)
                        if (elemName in CONTEXT_COMPONENT_ELEMENT_NAMES)
                            contextComponentClasses.add(cn)
                    }
                }
            }
            val next = pos.toLong() + size.toLong()
            if (next > fileSize.toLong()) break
            pos = next.toInt()
        }

        return ManifestTargets(manifestPkg, applicationClass, componentClasses,
                contextComponentClasses)
    }

    /**
     * The Android or unnamespaced attribute named by [name] on the start-element chunk at
     * [elemOff]. Element layout: +0 type/size, +8 lineNumber, +16 comment,
     * +20 name string idx, +24 attrStart(u16), +26 attrSize(u16),
     * +28 attrCount(u16); attributes begin at +16+attrStart, each is
     * ns(4) name(4) rawValue(4) typed(8: size,res0,dataType,data).
     */
    private fun readStringAttr(
        xml: ByteArray,
        elemOff: Int,
        elemSize: Int,
        name: String,
        namespaceIdx: Int?,
        strings: List<String>
    ): String? {
        val attrStart = u16(xml, elemOff + 24)
        val attrSize = u16(xml, elemOff + 26)
        val attrCount = u16(xml, elemOff + 28)
        require(attrSize >= 20) { "invalid AXML attribute size $attrSize" }
        require(attrBaseWithin(elemOff, elemSize, attrStart, attrCount, attrSize)) {
            "AXML attribute table lies outside the element"
        }
        val attrBase = elemOff + 16 + attrStart
        for (i in 0 until attrCount) {
            val off = attrBase + i * attrSize
            if (off + 20 > elemOff + elemSize) break
            val attrNamespace = u32(xml, off)
            val namespaceMatches = if (namespaceIdx == null) {
                attrNamespace == 0xFFFFFFFF.toInt()
            } else {
                namespaceIdx >= 0 && attrNamespace == namespaceIdx
            }
            if (!namespaceMatches || strings.getOrNull(u32(xml, off + 4)) != name) continue
            val rawIdx = u32(xml, off + 8)
            if (rawIdx != 0xFFFFFFFF.toInt() && rawIdx >= 0 && rawIdx < strings.size) {
                return strings[rawIdx]
            }
            val dataType = xml[off + 15].toInt() and 0xff
            if (dataType == TYPE_STRING) {
                val idx = u32(xml, off + 16)
                if (idx != 0xFFFFFFFF.toInt() && idx >= 0 && idx < strings.size) return strings[idx]
            }
        }
        return null
    }

    /** Reads manifest flags and optionally replaces the application class name
     *  in an existing string-pool slot. No chunks are inserted or resized.
     */
    fun patch(xml: ByteArray, replacementApplicationName: String? = null): PatchResult {
        val fileSize = minOf(u32(xml, 4), xml.size)
        val poolStart = findChunk(xml, 8, fileSize, RES_STRING_POOL_TYPE)
        val poolSize = u32(xml, poolStart + 4)
        val headerSize = u16(xml, poolStart + 2)
        val stringCount = u32(xml, poolStart + 8)
        val flags = u32(xml, poolStart + 16)
        val stringsStart = u32(xml, poolStart + 20)
        val isUtf8 = (flags and FLAG_UTF8) != 0
        validateStringPool(xml, fileSize, poolStart, poolSize, headerSize,
                stringCount, stringsStart)

        val strings = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            val off = u32(xml, poolStart + headerSize + i * 4)
            require(off >= 0 && off.toLong() < poolSize.toLong() - stringsStart.toLong()) {
                "string offset $off lies outside the string data"
            }
            val sOff = poolStart + stringsStart + off
            strings.add(if (isUtf8) readUtf8(xml, sOff) else readUtf16(xml, sOff))
        }

        val appNameIdx = strings.indexOf("application")
        if (appNameIdx < 0) error("'application' string not found in string pool")
        val androidNsIdx = strings.indexOf(ANDROID_NS_URI)

        var app = -1
        var pos = poolStart + poolSize
        while (pos + 8 <= fileSize) {
            val type = u16(xml, pos)
            val size = u32(xml, pos + 4)
            if (type == RES_XML_START_ELEMENT_TYPE &&
                    strings.getOrNull(u32(xml, pos + 20)) == "application") {
                app = pos
                break
            }
            if (size < 8) error("bad chunk size")
            val next = pos.toLong() + size.toLong()
            if (next > fileSize.toLong()) break
            pos = next.toInt()
        }
        if (app < 0) error("<application> element not found")
        val appSize = u32(xml, app + 4)
        val attrStart = u16(xml, app + 24)
        val attrSize = u16(xml, app + 26)
        val attrCount = u16(xml, app + 28)
        require(attrSize >= 20) { "invalid AXML attribute size $attrSize" }
        require(attrBaseWithin(app, appSize, attrStart, attrCount, attrSize)) {
            "application attribute table lies outside the element"
        }

        val attrBase = app + 16 + attrStart
        var extractNativeLibs = true
        var allowBackupPresent = false
        var allowBackupDisabled = false
        var applicationNamePatched = replacementApplicationName == null
        for (i in 0 until attrCount) {
            val off = attrBase + i * attrSize
            if (off + 20 > app + appSize) break
            val attrNamespace = u32(xml, off)
            val isAndroidAttr = androidNsIdx >= 0 && attrNamespace == androidNsIdx
            val nameIdx = u32(xml, off + 4)
            val attrName = strings.getOrNull(nameIdx)
            val dataType = xml[off + 15].toInt() and 0xff
            if (!applicationNamePatched && isAndroidAttr && attrName == "name") {
                val rawIdx = u32(xml, off + 8)
                val stringIdx = if (rawIdx != 0xFFFFFFFF.toInt()) rawIdx
                                else if (dataType == TYPE_STRING) u32(xml, off + 16)
                                else -1
                if (stringIdx < 0 || stringIdx >= strings.size ||
                        !replaceStringPoolEntry(
                            xml, poolStart, poolSize, headerSize, stringCount,
                            stringsStart, isUtf8, stringIdx, replacementApplicationName!!
                        )) {
                    error("application android:name cannot be replaced in place")
                }
                applicationNamePatched = true
            }
            if (isAndroidAttr && attrName == "allowBackup") {
                allowBackupPresent = true
            }
            if (dataType != TYPE_INT_BOOLEAN) continue
            if (isAndroidAttr && attrName == "extractNativeLibs" &&
                    u32(xml, off + 8) == 0xFFFFFFFF.toInt()) {
                extractNativeLibs = u32(xml, off + 16) != 0
            } else if (isAndroidAttr && attrName == "allowBackup" &&
                    u32(xml, off + 16) != 0) {
                putU32(xml, off + 8, -1)
                putU32(xml, off + 16, 0)
                allowBackupDisabled = true
            }
        }

        if (!applicationNamePatched)
            error("<application android:name> not found")
        return PatchResult(xml, extractNativeLibs, allowBackupDisabled, allowBackupPresent)
    }

    private fun replaceStringPoolEntry(
        xml: ByteArray,
        poolStart: Int,
        poolSize: Int,
        headerSize: Int,
        stringCount: Int,
        stringsStart: Int,
        isUtf8: Boolean,
        stringIdx: Int,
        replacement: String
    ): Boolean {
        val entryOffset = u32(xml, poolStart + headerSize + stringIdx * 4)
        val start = poolStart + stringsStart + entryOffset
        val poolEnd = poolStart + poolSize
        var end = poolEnd
        for (i in 0 until stringCount) {
            val other = u32(xml, poolStart + headerSize + i * 4)
            if (other > entryOffset) end = minOf(end, poolStart + stringsStart + other)
        }
        if (start < 0 || start > end || end > xml.size) return false

        /* A string-pool offset may be shared by multiple string IDs. Editing
         * that byte range would silently rewrite every attribute using it.
         * Refuse the in-place optimization; callers can use the safe hook path
         * or rebuild the pool instead. */
        var offsetReferences = 0
        for (i in 0 until stringCount) {
            if (u32(xml, poolStart + headerSize + i * 4) == entryOffset)
                offsetReferences++
        }
        if (offsetReferences != 1) return false

        if (isUtf8) {
            val bytes = replacement.toByteArray(Charsets.UTF_8)
            val utf16LengthBytes = if (replacement.length < 0x80) 1 else 2
            val byteLengthBytes = if (bytes.size < 0x80) 1 else 2
            val needed = utf16LengthBytes + byteLengthBytes + bytes.size + 1
            if (needed > end - start) return false
            var pos = start
            pos += writeLen8(xml, pos, replacement.length)
            pos += writeLen8(xml, pos, bytes.size)
            System.arraycopy(bytes, 0, xml, pos, bytes.size)
            xml[pos + bytes.size] = 0
        } else {
            val needed = 2 + replacement.length * 2 + 2
            if (needed > end - start) return false
            putU16(xml, start, replacement.length)
            var pos = start + 2
            for (ch in replacement) {
                putU16(xml, pos, ch.code)
                pos += 2
            }
            putU16(xml, pos, 0)
        }
        return true
    }

    private fun writeLen8(xml: ByteArray, off: Int, value: Int): Int {
        return if (value < 0x80) {
            xml[off] = value.toByte()
            1
        } else {
            xml[off] = (0x80 or (value ushr 8)).toByte()
            xml[off + 1] = value.toByte()
            2
        }
    }

    private fun putU16(d: ByteArray, o: Int, v: Int) {
        require(o >= 0 && o + 2 <= d.size) { "u16 write out of bounds: $o" }
        d[o] = (v and 0xff).toByte()
        d[o + 1] = ((v ushr 8) and 0xff).toByte()
    }

    private fun attrBaseWithin(
        elemOff: Int,
        elemSize: Int,
        attrStart: Int,
        attrCount: Int,
        attrSize: Int
    ): Boolean {
        val start = elemOff.toLong() + 16L + attrStart.toLong()
        val end = start + attrCount.toLong() * attrSize.toLong()
        return start >= elemOff.toLong() && end <= elemOff.toLong() + elemSize.toLong()
    }

    private fun findChunk(xml: ByteArray, from: Int, to: Int, type: Int): Int {
        var pos = from
        while (pos >= 0 && pos.toLong() + 8L <= to.toLong()) {
            if (u16(xml, pos) == type) return pos
            val size = u32(xml, pos + 4)
            if (size < 8) error("bad chunk size")
            val next = pos.toLong() + size.toLong()
            if (next > to.toLong()) break
            pos = next.toInt()
        }
        error("chunk type 0x" + type.toString(16) + " not found")
    }

    private fun readUtf8(xml: ByteArray, off: Int): String {
        var pos = off
        pos += len8FieldBytes(xml, pos)
        val byteLen = len8(xml, pos)
        pos += len8FieldBytes(xml, pos)
        val sb = StringBuilder()
        val end = minOf(pos + byteLen, xml.size)
        while (pos < end) {
            val b = xml[pos].toInt() and 0xff
            pos++
            when {
                b < 0x80 -> sb.append(b.toChar())
                b and 0xe0 == 0xc0 -> {
                    if (pos >= end) { sb.append('\uFFFD'); break }
                    val c = ((b and 0x1f) shl 6) or (xml[pos].toInt() and 0x3f)
                    pos++
                    sb.append(c.toChar())
                }
                b and 0xf0 == 0xe0 -> {
                    if (pos + 1 >= end) { sb.append('\uFFFD'); break }
                    val c = ((b and 0x0f) shl 12) or
                            ((xml[pos].toInt() and 0x3f) shl 6) or
                            (xml[pos + 1].toInt() and 0x3f)
                    pos += 2
                    sb.append(c.toChar())
                }
                else -> {
                    fun cont(o: Int): Int? {
                        if (o >= end) return null
                        val cb = xml[o].toInt() and 0xff
                        return if (cb and 0xc0 == 0x80) cb and 0x3f else null
                    }
                    val c1 = cont(pos)
                    val c2 = if (c1 != null) cont(pos + 1) else null
                    val c3 = if (c2 != null) cont(pos + 2) else null
                    val c = if (c1 != null && c2 != null && c3 != null)
                        ((b and 0x07) shl 18) or (c1 shl 12) or (c2 shl 6) or c3
                    else -1
                    if (c in 0x10000..0x10FFFF) {
                        pos += 3
                        sb.appendCodePoint(c)
                    } else {
                        sb.append('\uFFFD')
                    }
                }
            }
        }
        return sb.toString()
    }

    private fun len8(xml: ByteArray, off: Int): Int {
        val b = xml[off].toInt() and 0xff
        return if (b and 0x80 == 0) b
        else ((b and 0x7f) shl 8) or
                (if (off + 1 < xml.size) xml[off + 1].toInt() and 0xff else 0)
    }

    /** Bytes the UTF-8 length field at [off] occupies (1 or 2). */
    private fun len8FieldBytes(xml: ByteArray, off: Int): Int {
        val b = xml[off].toInt() and 0xff
        return if (b and 0x80 == 0) 1 else 2
    }

    private fun readUtf16(xml: ByteArray, off: Int): String {
        val len = maxOf(0, minOf(u16(xml, off), (xml.size - off - 2) / 2))
        val sb = StringBuilder(len)
        var pos = off + 2
        for (i in 0 until len) {
            sb.append(u16(xml, pos).toChar())
            pos += 2
        }
        return sb.toString()
    }

    private fun u16(d: ByteArray, o: Int): Int {
        require(o >= 0 && o + 2 <= d.size) { "u16 read out of bounds: $o in ${d.size}" }
        return (d[o].toInt() and 0xff) or ((d[o + 1].toInt() and 0xff) shl 8)
    }

    private fun u32(d: ByteArray, o: Int): Int {
        require(o >= 0 && o + 4 <= d.size) { "u32 read out of bounds: $o in ${d.size}" }
        return (d[o].toInt() and 0xff) or ((d[o + 1].toInt() and 0xff) shl 8) or
                ((d[o + 2].toInt() and 0xff) shl 16) or ((d[o + 3].toInt() and 0xff) shl 24)
    }

    private fun putU32(d: ByteArray, o: Int, v: Int) {
        require(o >= 0 && o + 4 <= d.size) { "u32 write out of bounds: $o in ${d.size}" }
        d[o] = (v and 0xff).toByte()
        d[o + 1] = ((v ushr 8) and 0xff).toByte()
        d[o + 2] = ((v ushr 16) and 0xff).toByte()
        d[o + 3] = (v ushr 24).toByte()
    }
}

/** Manifest bytes after in-place edits, plus native-library and backup flags. */
data class PatchResult(
    val bytes: ByteArray,
    val extractNativeLibs: Boolean,
    val allowBackupDisabled: Boolean = false,
    val allowBackupPresent: Boolean = false
)

/** The manifest pieces the virtualization whitelist is derived from. */
data class ManifestTargets(
    val manifestPackage: String?,
    val applicationClass: String?,
    /** android:name of every activity/service/receiver/provider, as written
     *  (may be relative - Packer resolves against manifestPackage).
     *  Whitelist seeding only; injection targets are [contextComponentClasses]. */
    val componentClasses: List<String> = emptyList(),
    /** Activities and services only - the only components DexRewriter may add
     *  attachBaseContext(Context)V to (see CONTEXT_COMPONENT_ELEMENT_NAMES). */
    val contextComponentClasses: List<String> = emptyList()
)
