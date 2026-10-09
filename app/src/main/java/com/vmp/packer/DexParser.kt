package com.vmp.packer

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile

/** Self-contained DEX parser used to select methods and build VMC metadata.
 * It reads standard ID/class/code tables and keys methods as
 * "$type|$name|$paramsConcat|$returnType" for correlation with dexlib2.
 */
class DexParser(
    private val dex: ByteArray,
    /** This pack's selection rules. Held rather than consulted from a singleton:
     *  DexRewriter and VmcWriter receive THIS parser, so the two passes cannot
     *  diverge by reading different policy. */
    val policy: PackPolicy,
    /** Where declines are recorded, for the pack log. */
    val skips: SkipLog
) {

    companion object {
        const val ACC_STATIC = 0x8
        const val ACC_SYNTHETIC = 0x1000
        const val ACC_NATIVE = 0x100
        const val ACC_INTERFACE = 0x200

        private const val OFF_STRING_IDS_SIZE = 0x38
        private const val OFF_STRING_IDS_OFF = 0x3c
        private const val OFF_TYPE_IDS_SIZE = 0x40
        private const val OFF_TYPE_IDS_OFF = 0x44
        private const val OFF_PROTO_IDS_SIZE = 0x48
        private const val OFF_PROTO_IDS_OFF = 0x4c
        private const val OFF_FIELD_IDS_SIZE = 0x50
        private const val OFF_FIELD_IDS_OFF = 0x54
        private const val OFF_METHOD_IDS_SIZE = 0x58
        private const val OFF_METHOD_IDS_OFF = 0x5c
        private const val OFF_CLASS_DEFS_SIZE = 0x60
        private const val OFF_CLASS_DEFS_OFF = 0x64

        internal const val MAX_INDEX_TABLE_BYTES = 64L * 1024L * 1024L
    }

    /** String id -> byte offset of the string_data_item. */
    private val stringIds: IntArray

    /** Type id -> string_id index (descriptor string). */
    private val typeIds: IntArray

    /** Proto id -> offset of proto_id_item (12 bytes each). */
    private val protoIds: IntArray

    /** Field id -> offset of field_id_item (8 bytes each). */
    private val fieldIds: IntArray

    /** Method id -> offset of method_id_item (8 bytes each). */
    private val methodIds: IntArray

    /** Class def id -> offset of class_def_item (32 bytes each). */
    private val classDefs: IntArray

    private val codeOffsets = HashMap<Int, Int>()
    private val accesses = HashMap<Int, Int>()
    private val keys = HashMap<Int, String>()
    private val keyToMidx = HashMap<String, Int>()
    private val insnsSizes = HashMap<Int, Int>()
    /** midx -> [registers_size, ins_size, outs_size], the code_item frame header
     *  (u2 at +0/+2/+4). This is the frame source: VmcWriter copies these values
     *  into the code table and PackPolicy's frame veto uses the same
     *  measurement, so both passes agree (see frameOf). */
    private val frames = HashMap<Int, IntArray>()
    private val interfaceClasses = HashSet<String>()
    private val classDescs = HashSet<String>()
    /** First unsupported native-interpreter opcode per method key. */
    private val unsupportedOpcodes = HashMap<String, String>()

    init {
        require(dex.size >= 0x70) { "DEX is smaller than the 0x70-byte header" }
        require(dex[0] == 'd'.code.toByte() && dex[1] == 'e'.code.toByte() &&
                dex[2] == 'x'.code.toByte() && dex[3] == '\n'.code.toByte() &&
                dex[7] == 0.toByte()) { "unsupported or malformed DEX magic" }
        require(u4(0x20) == dex.size) {
            "DEX header file_size ${u4(0x20)} does not match ${dex.size} bytes"
        }
        require(u4(0x24) == 0x70) { "unsupported DEX header size ${u4(0x24)}" }
        require(u4(0x28) == 0x12345678) { "unsupported DEX endian tag" }

        val stringsSize = u4(OFF_STRING_IDS_SIZE)
        val stringsOff = u4(OFF_STRING_IDS_OFF)
        val typesSize = u4(OFF_TYPE_IDS_SIZE)
        val typesOff = u4(OFF_TYPE_IDS_OFF)
        val protosSize = u4(OFF_PROTO_IDS_SIZE)
        val protosOff = u4(OFF_PROTO_IDS_OFF)
        val fieldsSize = u4(OFF_FIELD_IDS_SIZE)
        val fieldsOff = u4(OFF_FIELD_IDS_OFF)
        val methodsSize = u4(OFF_METHOD_IDS_SIZE)
        val methodsOff = u4(OFF_METHOD_IDS_OFF)
        val classDefsSize = u4(OFF_CLASS_DEFS_SIZE)
        val classDefsOff = u4(OFF_CLASS_DEFS_OFF)

        fun checkTable(name: String, count: Int, offset: Int, stride: Int) {
            require(count >= 0) { "$name count has the unsigned high bit set: $count" }
            if (count == 0) return
            require(offset >= 0 && offset >= 0x70 &&
                    offset.toLong() + count.toLong() * stride <= dex.size.toLong()) {
                "$name table count=$count offset=$offset stride=$stride is outside ${dex.size} bytes"
            }
        }
        checkTable("string_ids", stringsSize, stringsOff, 4)
        checkTable("type_ids", typesSize, typesOff, 4)
        checkTable("proto_ids", protosSize, protosOff, 12)
        checkTable("field_ids", fieldsSize, fieldsOff, 8)
        checkTable("method_ids", methodsSize, methodsOff, 8)
        checkTable("class_defs", classDefsSize, classDefsOff, 32)

        val indexTableBytes = stringsSize.toLong() * 4L +
                typesSize.toLong() * 4L +
                protosSize.toLong() * 12L +
                fieldsSize.toLong() * 8L +
                methodsSize.toLong() * 8L +
                classDefsSize.toLong() * 32L
        require(indexTableBytes <= MAX_INDEX_TABLE_BYTES) {
            "DEX index tables require $indexTableBytes bytes, " +
                    "exceeding the ${MAX_INDEX_TABLE_BYTES}-byte parser budget"
        }

        stringIds = IntArray(stringsSize) { u4(stringsOff + it * 4) }
        typeIds = IntArray(typesSize) { u4(typesOff + it * 4) }
        protoIds = IntArray(protosSize) { protosOff + it * 12 }
        fieldIds = IntArray(fieldsSize) { fieldsOff + it * 8 }
        methodIds = IntArray(methodsSize) { methodsOff + it * 8 }
        classDefs = IntArray(classDefsSize) { classDefsOff + it * 32 }

        parseClassDefs()
        indexUnsupportedOpcodes()
    }

    /**
     * Keep selection and rewriting conservative for opcode families that the
     * native interpreter cannot execute. dexlib2 is the authoritative decoder
     * here; the raw parser remains the authoritative frame/code-size reader.
     */
    private fun indexUnsupportedOpcodes() {
        val file = DexBackedDexFile(Opcodes.forApi(34), dex)
        for (classDef in file.classes) {
            for (method in classDef.methods) {
                val implementation = method.implementation ?: continue
                val params = method.parameters.joinToString("") { it.type }
                val key =
                    "${method.definingClass}|${method.name}|$params|${method.returnType}"
                InterpreterOpcodePolicy.firstUnsupported(implementation.instructions)
                    ?.let { unsupportedOpcodes[key] = it }
            }
        }
    }

    /** The raw bytes, exposed only for VmcWriter's dexlib2 reachability walk. */
    fun rawBytes(): ByteArray = dex

    /** Unsigned 32-bit little-endian value at [offset]. */
    fun u4(offset: Int): Int {
        require(offset >= 0 && offset + 4 <= dex.size) { "u4 read out of bounds: $offset" }
        return (dex[offset].toInt() and 0xff) or
                ((dex[offset + 1].toInt() and 0xff) shl 8) or
                ((dex[offset + 2].toInt() and 0xff) shl 16) or
                ((dex[offset + 3].toInt() and 0xff) shl 24)
    }

    /** Unsigned 16-bit little-endian value at [offset]. */
    fun u2(offset: Int): Int {
        require(offset >= 0 && offset + 2 <= dex.size) { "u2 read out of bounds: $offset" }
        return (dex[offset].toInt() and 0xff) or ((dex[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun u1(offset: Int): Int {
        require(offset >= 0 && offset < dex.size) { "u1 read out of bounds: $offset" }
        return dex[offset].toInt() and 0xff
    }

    /** ULEB128 value starting at [offset]; returns value, advances offset[0]. */
    fun uleb128(offset: IntArray): Int {
        var result = 0
        var shift = 0
        repeat(5) { index ->
            val b = u1(offset[0])
            offset[0]++
            if (index == 4) require(b and 0xf0 == 0) { "ULEB128 exceeds 32 bits" }
            result = result or ((b and 0x7f) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        error("ULEB128 exceeds 5 bytes")
    }

    /** SLEB128 value starting at [offset]; returns value, advances offset[0]. */
    fun sleb128(offset: IntArray): Int {
        var result = 0
        var shift = 0
        repeat(5) { index ->
            val b = u1(offset[0])
            offset[0]++
            result = result or ((b and 0x7f) shl shift)
            shift += 7
            if (b and 0x80 == 0) {
                if (index == 4) {
                    val top = b and 0x70
                    require(top == 0 || top == 0x70) { "SLEB128 exceeds 32 bits" }
                }
                if (shift < 32 && (b and 0x40) != 0)
                    result = result or (-1 shl shift)
                return result
            }
        }
        error("SLEB128 exceeds 5 bytes")
    }

    /** MUTF-8 string (length-prefixed) at [offset]. */
    fun strAt(offset: Int): String {
        val p = intArrayOf(offset)
        uleb128(p)
        val start = p[0]
        val end = findUtf8End(start)
        return decodeUtf8(start, end)
    }

    private fun findUtf8End(start: Int): Int {
        var i = start
        while (i < dex.size && dex[i].toInt() != 0) i++
        return i
    }

    private fun decodeUtf8(start: Int, end: Int): String {
        val bytes = ByteArray(end - start)
        for (i in start until end) bytes[i - start] = dex[i]
        val out = StringBuilder()
        var i = 0
        while (i < bytes.size) {
            val b = bytes[i].toInt() and 0xff
            if (b < 0x80) {
                if (b == 0) {
                    out.append('\u0000')
                } else {
                    out.append(b.toChar())
                }
                i++
            } else if (b and 0xe0 == 0xc0) {
                if (i + 2 > bytes.size) { out.append('\uFFFD'); break }
                val c = ((b and 0x1f) shl 6) or (bytes[i + 1].toInt() and 0x3f)
                out.append(c.toChar())
                i += 2
            } else if (b and 0xf0 == 0xe0) {
                if (i + 3 > bytes.size) { out.append('\uFFFD'); break }
                val c = ((b and 0x0f) shl 12) or
                        ((bytes[i + 1].toInt() and 0x3f) shl 6) or
                        (bytes[i + 2].toInt() and 0x3f)
                out.append(c.toChar())
                i += 3
            } else {
                if (i + 4 > bytes.size) { out.append('\uFFFD'); break }
                val c = ((b and 0x07) shl 18) or
                        ((bytes[i + 1].toInt() and 0x3f) shl 12) or
                        ((bytes[i + 2].toInt() and 0x3f) shl 6) or
                        (bytes[i + 3].toInt() and 0x3f)
                out.appendCodePoint(c)
                i += 4
            }
        }
        return out.toString()
    }

    /** String at string_id index [idx]. */
    fun stringByIdx(idx: Int): String {
        if (idx < 0 || idx >= stringIds.size) return "<bad-string-$idx>"
        return strAt(stringIds[idx])
    }

    /** Type descriptor ("Lcom/foo/Bar;", "I", ...) for type index [idx]. */
    fun typeDesc(idx: Int): String {
        if (idx < 0 || idx >= typeIds.size) return "<bad-type-$idx>"
        return stringByIdx(typeIds[idx])
    }

    /** Shorty string for proto index [idx] ("V", "II", "Ljava/lang/String;I", ...). */
    fun protoShorty(idx: Int): String {
        if (idx < 0 || idx >= protoIds.size) return "V"
        val off = protoIds[idx]
        val shortyIdx = u4(off)
        return stringByIdx(shortyIdx)
    }

    /**
     * JNI signature for proto index [idx], e.g. "(I)Ljava/lang/String;".
     */
    fun jniSig(idx: Int): String {
        if (idx < 0 || idx >= protoIds.size) return "()V"
        val off = protoIds[idx]
        val retTypeIdx = u4(off + 4)
        val paramsOff = u4(off + 8)
        val sb = StringBuilder()
        sb.append('(')
        if (paramsOff != 0) {
            val size = u4(paramsOff)
            for (i in 0 until size) {
                sb.append(typeDesc(u2(paramsOff + 4 + i * 2)))
            }
        }
        sb.append(')').append(typeDesc(retTypeIdx))
        return sb.toString()
    }

    private fun parseClassDefs() {
        for (cd in classDefs) {
            val classTypeIdx = u4(cd)
            classDescs.add(typeDesc(classTypeIdx))
            val accessFlags = u4(cd + 4)
            if ((accessFlags and ACC_INTERFACE) != 0) {
                interfaceClasses.add(typeDesc(classTypeIdx))
            }
            val classDataOff = u4(cd + 24)
            if (classDataOff == 0) continue
            parseClassData(classDataOff)
        }
    }

    /** encoded_class_data_item: static fields, instance fields, then direct
     *  and virtual methods. Only entries with a code_off that are not native
     *  become virtualization candidates. */
    private fun parseClassData(classDataOff: Int) {
        val p = intArrayOf(classDataOff)
        val staticFieldsSize = uleb128(p)
        val instanceFieldsSize = uleb128(p)
        val directMethodsSize = uleb128(p)
        val virtualMethodsSize = uleb128(p)

        repeat(staticFieldsSize + instanceFieldsSize) {
            uleb128(p)
            uleb128(p)
        }

        parseMethodList(p, directMethodsSize)
        parseMethodList(p, virtualMethodsSize)
    }

    private fun parseMethodList(p: IntArray, size: Int) {
        var methodIdx = 0
        for (i in 0 until size) {
            val diff = uleb128(p)
            methodIdx += diff
            val access = uleb128(p)
            val codeOff = uleb128(p)

            if (codeOff != 0 && (access and ACC_NATIVE) == 0) {
                require(codeOff >= 0 && codeOff <= dex.size - 16) {
                    "code_item offset $codeOff is outside the dex file"
                }
                val registersSize = u2(codeOff)
                val insSize = u2(codeOff + 2)
                val outsSize = u2(codeOff + 4)
                val expectedInsSize = parameterWordCount(methodIdx, access)
                require(insSize == expectedInsSize && expectedInsSize <= registersSize) {
                    val key = buildKey(methodIdx)
                    "invalid code_item frame for $key: registers_size=$registersSize, " +
                            "ins_size=$insSize, expected_ins_size=$expectedInsSize, " +
                            "outs_size=$outsSize, code_off=$codeOff"
                }
                codeOffsets[methodIdx] = codeOff
                accesses[methodIdx] = access
                insnsSizes[methodIdx] = u4(codeOff + 12)
                frames[methodIdx] = intArrayOf(registersSize, insSize, outsSize)
                val key = buildKey(methodIdx)
                keys[methodIdx] = key
                keyToMidx[key] = methodIdx
            }
        }
    }

    private fun parameterWordCount(midx: Int, access: Int): Int {
        val methodOff = methodIds[midx]
        val protoIdx = u2(methodOff + 2)
        val protoOff = protoIds[protoIdx]
        val paramsOff = u4(protoOff + 8)
        var words = if ((access and ACC_STATIC) == 0) 1 else 0
        if (paramsOff != 0) {
            val count = u4(paramsOff)
            for (i in 0 until count) {
                val type = typeDesc(u2(paramsOff + 4 + i * 2))
                words += if (type == "J" || type == "D") 2 else 1
            }
        }
        return words
    }

    private fun buildKey(midx: Int): String {
        val off = methodIds[midx]
        val typeIdx = u2(off)
        val protoIdx = u2(off + 2)
        val nameIdx = u4(off + 4)
        val type = typeDesc(typeIdx)
        val name = stringByIdx(nameIdx)
        val protoOff = protoIds[protoIdx]
        val paramsOff = u4(protoOff + 8)
        val params = StringBuilder()
        if (paramsOff != 0) {
            val n = u4(paramsOff)
            for (i in 0 until n) {
                params.append(typeDesc(u2(paramsOff + 4 + i * 2)))
            }
        }
        val retType = typeDesc(u4(protoOff + 4))
        return "$type|$name|$params|$retType"
    }

    /** Reads the code_item at [codeOff] and returns the flattened data. */
    fun readCode(codeOff: Int): DexCode {
        val regs = u2(codeOff)
        val ins = u2(codeOff + 2)
        val outs = u2(codeOff + 4)
        val triesSize = u2(codeOff + 6)
        val insnsSize = u4(codeOff + 12)
        val insnsOff = codeOff + 16

        val insnsEnd = insnsOff.toLong() + insnsSize.toLong() * 2L
        require(insnsSize >= 0 && insnsEnd <= dex.size.toLong()) {
            "code_item at $codeOff declares $insnsSize code units at $insnsOff, " +
                    "past the end of a ${dex.size}-byte dex"
        }
        val insns = ByteArray(insnsSize * 2)
        System.arraycopy(dex, insnsOff, insns, 0, insns.size)

        var triesOff = insnsOff + insnsSize * 2
        if (triesSize > 0) {
            triesOff = (triesOff + 3) and -4
        }
        val handlersEnd = triesOff.toLong() + triesSize.toLong() * 8L
        require(triesSize == 0 || handlersEnd + 4L <= dex.size.toLong()) {
            "$triesSize try items at $triesOff run past a ${dex.size}-byte dex"
        }
        val handlersOff = handlersEnd.toInt()

        val flatTries = if (triesSize > 0) flattenTryItems(triesOff, triesSize, handlersOff) else ByteArray(0)

        return DexCode(
            regs = regs,
            ins = ins,
            outs = outs,
            insnsSize = insnsSize,
            insns = insns,
            flatTries = flatTries,
            flatTriesCount = flatTries.size / 16
        )
    }

    /**
     * Flattens try_items + encoded_catch_handler_list into 16-byte
     * (start, count, typeIdx, addr) records - the shape the native interpreter
     * searches to locate and type-match a handler. typeIdx -1 is the catch-all.
     */
    private fun flattenTryItems(triesOff: Int, triesSize: Int, handlersOff: Int): ByteArray {
        val sb = java.io.ByteArrayOutputStream()
        fun writeInt(v: Int) {
            sb.write(v and 0xff); sb.write((v shr 8) and 0xff)
            sb.write((v shr 16) and 0xff); sb.write((v shr 24) and 0xff)
        }
        val p = intArrayOf(handlersOff)
        val numHandlers = uleb128(p)
        val recordOffsets = mutableListOf<Int>()
        val records = mutableListOf<List<Pair<Int, Int>>>()
        for (i in 0 until numHandlers) {
            recordOffsets.add(p[0] - handlersOff)
            val size = sleb128(p)
            val count = Math.abs(size)
            val hasCatchAll = size <= 0
            val entries = mutableListOf<Pair<Int, Int>>()
            for (j in 0 until count) {
                entries.add(uleb128(p) to uleb128(p))
            }
            if (hasCatchAll) entries.add(-1 to uleb128(p))
            records.add(entries)
        }
        val offToIndex = HashMap<Int, Int>()
        for ((i, off) in recordOffsets.withIndex()) offToIndex[off] = i
        for (i in 0 until triesSize) {
            val start = u4(triesOff + i * 8)
            val count = u2(triesOff + i * 8 + 4)
            val hoff = u2(triesOff + i * 8 + 6)
            val recIdx = offToIndex[hoff] ?: -1
            if (recIdx < 0) continue
            for ((ty, ad) in records[recIdx]) {
                writeInt(start); writeInt(count); writeInt(ty); writeInt(ad)
            }
        }
        return sb.toByteArray()
    }

    /** All method indices that have code (the virtualizable set). */
    fun keysWithCode(): Set<String> = keys.values.toSet()

    /**
     * The subset of keysWithCode() actually virtualized, decided by the same
     * PackPolicy call DexRewriter makes. VmcWriter builds its code table from
     * this, so the code-table index and the native stubs stay in step.
     */
    fun virtualizableKeys(selectionPolicy: PackPolicy = policy): Set<String> =
        keysWithCode().filterTo(HashSet()) { key ->
            val parts = key.split('|')
            val type = parts[0]
            val name = parts.getOrElse(1) { "" }
            val params = parts.getOrElse(2) { "" }
            val retType = parts.getOrElse(3) { "" }
            val isInterface = type in interfaceClasses
            val isConstructor = name == "<init>" || name == "<clinit>"
            val f = keyToMidx[key]?.let { frames[it] }
            selectionPolicy.shouldVirtualize(
                type, name, params, retType, isInterface, isConstructor,
                instructionCount = insnsSizeOf(key),
                registersSize = f?.get(0) ?: 0,
                insSize = f?.get(1) ?: 0,
                outsSize = f?.get(2) ?: 0,
                skips = skips,
                unsupportedOpcode = unsupportedOpcodeOf(key),
                isSynthetic = (accessOf(key) and ACC_SYNTHETIC) != 0
            )
        }

    fun unsupportedOpcodeOf(key: String): String? = unsupportedOpcodes[key]

    fun codeOf(key: String): DexCode? {
        val midx = keyToMidx[key] ?: return null
        val off = codeOffsets[midx] ?: return null
        return readCode(off)
    }

    /** 16-bit code units of the method with the given key (0 when none). */
    fun insnsSizeOf(key: String): Int {
        val midx = keyToMidx[key] ?: return 0
        return insnsSizes[midx] ?: 0
    }

    /** Frame header [registers_size, ins_size, outs_size] for [key], or null.
     *  VmcWriter and DexRewriter are handed THIS parser instance - one
     *  measurement, so the two passes cannot disagree. */
    fun frameOf(key: String): IntArray? = keyToMidx[key]?.let { frames[it] }

    /** True when this dex defines the given class descriptor. */
    fun hasClass(desc: String): Boolean = desc in classDescs

    fun accessOf(key: String): Int = keyToMidx[key]?.let { accesses[it] } ?: 0

    fun midxOf(key: String): Int = keyToMidx[key] ?: -1

    /** Proto index -> shorty string, used by the native side through VMC. */
    fun protoShortyByIdx(idx: Int): String = protoShorty(idx)

    /** Proto index -> param type descriptor list (for the VMC param table). */
    fun protoParams(idx: Int): List<String> {
        if (idx < 0 || idx >= protoIds.size) return emptyList()
        val off = protoIds[idx]
        val paramsOff = u4(off + 8)
        if (paramsOff == 0) return emptyList()
        val n = u4(paramsOff)
        return List(n) { typeDesc(u2(paramsOff + 4 + it * 2)) }
    }

    fun stringCount(): Int = stringIds.size
    fun typeCount(): Int = typeIds.size
    fun protoCount(): Int = protoIds.size
    fun fieldCount(): Int = fieldIds.size
    fun methodCount(): Int = methodIds.size
    fun classDefCount(): Int = classDefs.size

    fun methodIdOffset(idx: Int): Int = methodIds[idx]
    fun fieldIdOffset(idx: Int): Int = fieldIds[idx]
}

/**
 * Parsed code_item contents (raw byte arrays kept so VmcWriter can copy them).
 */
data class DexCode(
    val regs: Int,
    val ins: Int,
    val outs: Int,
    val insnsSize: Int,
    val insns: ByteArray,
    val flatTries: ByteArray = ByteArray(0),
    val flatTriesCount: Int = 0
)
