package com.vmp.packer

import java.security.MessageDigest

/**
 * IR codec (post-Dalvik program). A method's code-unit stream is stored in
 * the container as fixed 16-byte records - zero-padded. Wide instructions
 * (payload bodies) span consecutive records; widths[] counts units PER
 * RECORD (1..8) and re-expansion is pure concatenation.
 *
 * v2/v2.1: footprint-preserving superinstructions fold common glue:
 *   iput(+-typed/wide) + return-void            -> FUSE_SETTER
 *   iget(+-typed/wide) + return(-wide/-object)  -> FUSE_GETTER
 *   const/16 + return (same register)            -> FUSE_CONST
 *   const-wide/16 + return-wide (same register)  -> FUSE_CONSTW        [2.1]
 *   iput + invoke + return-void                  -> FUSE_SETTER_INVOKE [2.1]
 *   iget + if-eqz/if-nez                         -> FUSE_GETTER_IF     [2.1]
 * Each rewrites ONLY the first instruction's opcode byte; every following
 * instruction stays byte-exact at its real address and runs its normal
 * handler, so return semantics, branch targets, handler addresses and pc
 * arithmetic never move. The original opcode never dispatches - the fused
 * case derives get/put from the MARKER and the field width from the field
 * descriptor, so the whole typed/wide families are as safe as int/object.
 * Fusion happens only when no branch/switch target lands on a covered
 * interior start and the method has no try items (checked by caller).
 *
 * Opcode bytes are permuted (canonical -> stored, the record method's LUT)
 * AFTER fusion; the digest covers the FINAL canonical (fused, pre-permute)
 * stream and is checked by the runtime post-un-permute.
 *
 * Lossless and SELF-VERIFIED: encode() re-expands its own output and
 * compares byte-for-byte; a null return means "stay canonical".
 * Widths come from dexlib2's insn-start list (the single sanctioned walker).
 *
 * Negotiation: IR_ACCESS_BIT in the code-table access word; IR needs cap
 * >= IR_MIN_CAP with the multi-LUT permute active; v2.0 patterns need cap
 * >= IR_FUSE_CAP, v2.1 patterns cap >= IR_FUSE2_CAP. The per-build mask
 * selects which patterns are emitted; the runtime carries handlers for
 * every marker. Section layout (header slots 96/100):
 *
 *   ir + 0        : u32 record count (== code-table record count)
 *   ir + 4        : u32 table offset per record, code-table order (0 = canon)
 *   ir + 4 + 4*n  : u32 fusedTotal (informational; runtime ignores)
 *   tables        : per IR method: u16 recordCount, u16 widths[recordCount],
 *                   u8 sha256[32]
 */
object IrCodec {

    const val REC = 16
    const val IR_ACCESS_BIT = 0x10000000
    const val IR_MIN_CAP = 8
    const val IR_FUSE_CAP = 9
    const val IR_FUSE2_CAP = 10
    const val IR_OFF_SLOT = 96
    const val IR_SIZE_SLOT = 100

    const val FUSE_SETTER = 0xfa
    const val FUSE_GETTER = 0xfb
    const val FUSE_CONST = 0xfc
    const val FUSE_CONSTW = 0xfd
    const val FUSE_SETTER_INVOKE = 0xfe
    const val FUSE_GETTER_IF = 0xff

    const val P_SETTER = 0x01
    const val P_GETTER = 0x02
    const val P_CONST = 0x04
    const val P_CONSTW = 0x08
    const val P_SETTER_INVOKE = 0x10
    const val P_GETTER_IF = 0x20
    const val P_V20 = 0x07
    const val P_ALL = 0x3f


    private const val RETURN_VOID = 0x0e
    private const val RETURN = 0x0f
    private const val RETURN_WIDE = 0x10
    private const val RETURN_OBJECT = 0x11
    private const val CONST_16 = 0x13
    private const val CONST_W16 = 0x16
    private const val IF_EQZ = 0x38
    private const val IF_NEZ = 0x39
    private val INVOKE_OPS = (0x6e..0x78).toSet()
    private val FUSE_IPUT = (0x59..0x5f).toSet()
    private val FUSE_IGET = (0x52..0x58).toSet()

    class Encoded(
        val records: ByteArray,
        val widths: IntArray,
        val totalUnits: Int,
        val sha256: ByteArray,
        val fused: Int
    )

    /**
     * Encode one method. lut (stored->canonical, the perm section's table
     * for this record) is applied to opcode bytes after fusion. targets =
     * protected jump-target addresses (null disables fusion); patterns =
     * this build's mask. Returns null (= keep canonical) on inconsistent
     * starts or a failed internal round-trip; a null is a coverage loss,
     * never a correctness risk.
     */
    fun encode(insns: ByteArray, starts: IntArray, insnsSize: Int,
               lut: ByteArray? = null, targets: IntArray? = null,
               patterns: Int = 0,
               onFuse: ((s: Int, marker: Int, op0: Int, op1: Int) -> Unit)? = null
    ): Encoded? {
        if (starts.isEmpty() || insnsSize <= 0) return null
        if (starts[0] != 0) return null
        for (i in starts.indices) {
            val s = starts[i]
            if (s < 0 || s >= insnsSize) return null
            if (i > 0 && starts[i] <= starts[i - 1]) return null
        }
        val totalUnits = insnsSize * 2
        val stream = ByteArray(totalUnits)
        System.arraycopy(insns, 0, stream, 0, totalUnits)

        for (s in starts) {
            val opByte = stream[2 * s].toInt() and 0xff
            if (opByte in 0xfa..0xff) return null
        }

        val fused = if (targets != null && patterns != 0)
            fusePatterns(stream, starts, insnsSize, targets.toHashSet(), patterns, onFuse)
        else 0

        val sha = MessageDigest.getInstance("SHA-256").digest(stream)

        if (lut != null) {
            val inv = IntArray(256)
            for (j in 0 until 256) inv[lut[j].toInt() and 0xff] = j
            for (s in starts) {
                val pos = 2 * s
                stream[pos] = inv[stream[pos].toInt() and 0xff].toByte()
            }
        }

        val ws = ArrayList<Int>(starts.size + 8)
        for (i in starts.indices) {
            val end = if (i + 1 < starts.size) starts[i + 1] else insnsSize
            var rem = end - starts[i]
            if (rem < 1) return null
            while (rem > 0) { val c = if (rem > 8) 8 else rem; ws.add(c); rem -= c }
        }
        val widths = ws.toIntArray()
        val records = ByteArray(widths.size * REC)
        run {
            var ri = 0
            for (i in starts.indices) {
                val end = if (i + 1 < starts.size) starts[i + 1] else insnsSize
                var off = starts[i]
                while (off < end) {
                    val c = if (end - off > 8) 8 else end - off
                    System.arraycopy(stream, 2 * off, records, ri * REC, 2 * c)
                    off += c; ri++
                }
            }
        }

        val back = decode(records, widths) ?: return null
        if (back.size != totalUnits) return null
        for (j in 0 until totalUnits) if (back[j] != stream[j]) return null

        return Encoded(records, widths, insnsSize, sha, fused)
    }

    /** Fold patterns in place; returns count fused. Op-byte-only rewrites:
     *  the marker replaces the FIRST instruction's opcode; every following
     *  instruction stays byte-exact at its real address and runs its normal
     *  handler. Covered interior starts must not be jump targets. */
    private fun fusePatterns(stream: ByteArray, starts: IntArray, insnsSize: Int,
                             prot: HashSet<Int>, patterns: Int,
                             onFuse: ((Int, Int, Int, Int) -> Unit)?): Int {
        var fused = 0
        var i = 0
        val n = starts.size
        while (i < n) {
            val s = starts[i]
            val op = stream[2 * s].toInt() and 0xff
            var did = false
            var consumed = 1
            if (i + 1 < n) {
                val s1 = starts[i + 1]
                val end1 = if (i + 2 < n) starts[i + 2] else insnsSize
                val w0 = s1 - s
                val w1 = end1 - s1
                val op1 = stream[2 * s1].toInt() and 0xff
                if (s1 !in prot && w0 == 2) {
                    val regA = stream[2 * s + 1].toInt() and 0xff
                    val reg1 = stream[2 * s1 + 1].toInt() and 0xff
                    var marker = -1
                    when {
                        (patterns and P_SETTER) != 0 && w1 == 1 &&
                                op in FUSE_IPUT && op1 == RETURN_VOID -> marker = FUSE_SETTER
                        (patterns and P_GETTER) != 0 && w1 == 1 &&
                                op in FUSE_IGET && (op1 == RETURN ||
                                        op1 == RETURN_WIDE || op1 == RETURN_OBJECT) -> marker = FUSE_GETTER
                        (patterns and P_CONST) != 0 && w1 == 1 &&
                                op == CONST_16 && op1 == RETURN && regA == reg1 -> marker = FUSE_CONST
                        (patterns and P_CONSTW) != 0 && w1 == 1 &&
                                op == CONST_W16 && op1 == RETURN_WIDE && regA == reg1 -> marker = FUSE_CONSTW
                        (patterns and P_GETTER_IF) != 0 && w1 == 2 &&
                                op in FUSE_IGET && (op1 == IF_EQZ || op1 == IF_NEZ) -> marker = FUSE_GETTER_IF
                    }
                    if (marker >= 0) {
                        stream[2 * s] = marker.toByte()
                        did = true; consumed = 2
                        onFuse?.invoke(s, marker, op, op1)
                    }
                }
            }
            if (!did && (patterns and P_SETTER_INVOKE) != 0 && i + 2 < n) {
                val s1 = starts[i + 1]
                val s2 = starts[i + 2]
                val end2 = if (i + 3 < n) starts[i + 3] else insnsSize
                if (s1 !in prot && s2 !in prot && s1 - s == 2 &&
                        s2 - s1 in 3..8 && end2 - s2 == 1 &&
                        op in FUSE_IPUT &&
                        (stream[2 * s1].toInt() and 0xff) in INVOKE_OPS &&
                        (stream[2 * s2].toInt() and 0xff) == RETURN_VOID) {
                    stream[2 * s] = FUSE_SETTER_INVOKE.toByte()
                    did = true; consumed = 3
                    onFuse?.invoke(s, FUSE_SETTER_INVOKE, op,
                            stream[2 * s1].toInt() and 0xff)
                }
            }
            if (did) { fused++; i += consumed } else i += 1
        }
        return fused
    }

    /** Records -> (permuted) code-unit bytes. Mirrors vmp_ir.cpp. */
    fun decode(records: ByteArray, widths: IntArray): ByteArray? {
        if (records.size != widths.size * REC) return null
        var total = 0
        for (w in widths) { if (w < 1 || w > 8) return null; total += w }
        val out = ByteArray(total * 2)
        var pos = 0
        for (i in widths.indices) {
            System.arraycopy(records, i * REC, out, pos, widths[i] * 2)
            pos += widths[i] * 2
        }
        return out
    }
}
