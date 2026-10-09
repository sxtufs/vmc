package com.vmp.packer

import java.security.SecureRandom
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction

/** Per-output opcode permutation. The packer records instruction starts from
 * dexlib2, stores canonical opcodes through a bijective LUT, and the runtime
 * restores them during first execution. Header slot 92 points to the section;
 * version 4 uses one LUT and version 5 uses eight LUTs with per-record selectors.
 */
object InsnPerm {

    const val LUT_SIZE = 256
    const val PERM_OFF_SLOT = 92

    /** Independent LUTs in the v5 section. */
    const val PERM_LUT_COUNT = 8

    /** Lowest vmp.abi.N token whose runtime parses v5 multi-LUT blobs. */
    const val MULTI_PERM_CAP = 7

    /** Key format identical to DexParser: "type|name|paramsConcat|ret". */
    private fun keyOf(type: String, name: String, params: String, ret: String): String =
        "$type|$name|$params|$ret"

    private fun i32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
                ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    private fun u16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)

    /**
     * dexlib2 walk of [dexBytes]: insn-start offsets (code units) for every key
     * in [keys]. [insnsSizeOf] supplies each key's DECLARED code_item size from
     * the independent binary parser; the walk must sum to it. That cross-parser
     * comparison is the drift guard (checking dexlib2 against itself proves
     * nothing). Throws if a key is missing or sizes disagree; callers treat a
     * throw as "do not permute this dex", never as a half-permuted blob.
     */
    fun collectStarts(
        dexBytes: ByteArray,
        keys: Collection<String>,
        insnsSizeOf: (String) -> Int
    ): Map<String, IntArray> {
        val df = DexBackedDexFile(Opcodes.forApi(34), dexBytes)
        val wanted = HashSet(keys)
        val out = HashMap<String, IntArray>(keys.size)
        for (cls in df.classes) {
            for (m in cls.methods) {
                if (wanted.isEmpty()) break
                val impl = m.implementation ?: continue
                val params = StringBuilder()
                for (p in m.parameters) params.append(p.type)
                val key = keyOf(m.definingClass, m.name, params.toString(), m.returnType)
                if (!wanted.remove(key)) continue
                val starts = ArrayList<Int>(16)
                var units = 0
                for (ins in impl.instructions) {
                    starts.add(units)
                    units += ins.codeUnits
                }
                val declared = insnsSizeOf(key)
                if (declared <= 0)
                    throw IllegalStateException("parser lost code size for $key")
                if (units != declared)
                    throw IllegalStateException("walk size drift on $key: $units != $declared")
                out[key] = starts.toIntArray()
            }
        }
        if (wanted.isNotEmpty())
            throw IllegalStateException("no walkable code for ${wanted.size} key(s), e.g. ${wanted.first()}")
        return out
    }

    /**
     * Absolute code-unit addresses that branches/switches can land on, per key:
     * a fusion footprint interior must never be a jump target. Same walker and
     * key format as collectStarts.
     * A key is ABSENT (never fuse this method) when the walk cannot model it
     * conservatively: payload pseudo-instructions present, or the
     * OffsetInstruction accessor unreadable (getCodeOffset is resolved
     * reflectively so an API difference degrades to "do not fuse").
     * Present key with empty array = branch-free, fuse-friendly.
     */
    fun collectTargets(
        dexBytes: ByteArray,
        keys: Collection<String>,
        insnsSizeOf: (String) -> Int
    ): Map<String, IntArray> {
        val df = DexBackedDexFile(Opcodes.forApi(34), dexBytes)
        val wanted = HashSet(keys)
        val out = HashMap<String, IntArray>()
        for (cls in df.classes) {
            for (m in cls.methods) {
                if (wanted.isEmpty()) break
                val impl = m.implementation ?: continue
                val params = StringBuilder()
                for (p in m.parameters) params.append(p.type)
                val key = keyOf(m.definingClass, m.name, params.toString(), m.returnType)
                if (!wanted.remove(key)) continue
                val t = ArrayList<Int>(4)
                var fusable = true
                var units = 0
                for (ins in impl.instructions) {
                    if (ins.javaClass.name.contains("Payload")) fusable = false
                    if (ins is OffsetInstruction) {
                        try {
                            val off = OffsetInstruction::class.java
                                    .getMethod("getCodeOffset").invoke(ins) as Int
                            t.add(units + off)
                        } catch (e: Exception) { fusable = false }
                    }
                    units += ins.codeUnits
                }
                if (fusable) out[key] = t.toIntArray()
            }
        }
        return out
    }

    /** A fresh opcode bijection in stored->canonical direction (never identity). */
    fun generateLut(): ByteArray {
        val rnd = SecureRandom()
        while (true) {
            val lut = ByteArray(256) { it.toByte() }
            for (i in 255 downTo 1) {
                val j = rnd.nextInt(i + 1)
                val t = lut[i]; lut[i] = lut[j]; lut[j] = t
            }
            var identity = true
            for (i in 0 until 256) if (lut[i] != i.toByte()) { identity = false; break }
            if (!identity) return lut
        }
    }

    /**
     * Apply the blob's perm section to every recorded insn start.
     * s2c=false maps canonical->stored (pack time, before encryption);
     * s2c=true restores stored->canonical (runtime direction, and SelfTest's
     * round-trip). Validates everything before writing - a partial application
     * could never be undone - and returns false with the blob untouched.
     */
    fun applyToBlob(blob: ByteArray, s2c: Boolean, multi: Boolean = false): Boolean {
        if (blob.size < 112) return false
        if (i32(blob, 4) > 2) return false
        val permOff = i32(blob, PERM_OFF_SLOT)
        val fileSize = i32(blob, 8)
        if (fileSize < 112 || fileSize > blob.size) return false
        if (permOff < 112) return false
        val permSize = fileSize - permOff
        val codeSize = i32(blob, 68)
        val codeOff = i32(blob, 72)
        val dataOff = i32(blob, 80)
        if (codeSize % 36 != 0) return false
        val n = codeSize / 36
        val nLut = if (multi) PERM_LUT_COUNT else 1
        val lutArea = nLut * LUT_SIZE
        val idxBase = lutArea + (if (multi) n else 0)
        if (permSize < idxBase + 4 * n + 2) return false

        val eff = ArrayList<IntArray>(nLut)
        for (l in 0 until nLut) {
            val map = IntArray(LUT_SIZE) { i -> blob[permOff + l * LUT_SIZE + i].toInt() and 0xff }
            val seen = BooleanArray(LUT_SIZE)
            for (v in map) { if (seen[v]) return false; seen[v] = true }
            if (s2c) eff.add(map)
            else eff.add(IntArray(LUT_SIZE).also { inv -> for (i in map.indices) inv[map[i]] = i })
        }
        if (multi)
            for (r in 0 until n)
                if ((blob[permOff + lutArea + r].toInt() and 0xff) >= nLut) return false

        val rels = IntArray(n)
        val counts = IntArray(n)
        val bases = IntArray(n)
        val luts = IntArray(n) { if (multi) blob[permOff + lutArea + it].toInt() and 0xff else 0 }
        for (r in 0 until n) {
            val rec = codeOff + r * 36
            if (rec + 36 > permOff) return false
            if (i32(blob, rec + 4) and IrCodec.IR_ACCESS_BIT != 0) {
                rels[r] = 0; counts[r] = 0; bases[r] = 0
                continue
            }
            val rel = i32(blob, permOff + idxBase + 4 * r)
            if (rel < idxBase + 4 * n || rel + 2 > permSize) return false
            val count = u16(blob, permOff + rel)
            if (count < 1 || rel + 2 + 2 * count > permSize) return false
            val insnsSize = i32(blob, rec + 20)
            val insnsOff = i32(blob, rec + 24)
            if (insnsOff < 0 || insnsSize < 0 ||
                    dataOff.toLong() + insnsOff + insnsSize * 2L > fileSize) return false
            var prev = -1
            for (j in 0 until count) {
                val s = u16(blob, permOff + rel + 2 + 2 * j)
                if ((j == 0 && s != 0) || (j > 0 && s <= prev) || s >= insnsSize) return false
                prev = s
            }
            rels[r] = rel; counts[r] = count; bases[r] = dataOff + insnsOff
        }
        for (r in 0 until n) {
            val lut = eff[luts[r]]
            val rel = rels[r]
            for (j in 0 until counts[r]) {
                val s = u16(blob, permOff + rel + 2 + 2 * j)
                val pos = bases[r] + s * 2
                blob[pos] = lut[blob[pos].toInt() and 0xff].toByte()
            }
        }
        return true
    }
}
