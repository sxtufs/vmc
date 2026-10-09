package com.vmp.packer

import android.content.Context
import java.io.File

/**
 * In-process structural self-test for the VMC container.
 *
 * Runs inside the packer, over its own dex, when Debug Mode is on.
 *
 * The checks are about STRUCTURE, not semantics: header fields, section bounds
 * and non-overlap, string offsets, proto-table walking, code-record size - the
 * invariants that produce a blob the runtime mis-parses.
 *
 * Failures are reported without aborting the pack.
 */
object SelfTest {

    private const val HEADER = 112

    private val SEC_NAMES = arrayOf(
        "strings", "types", "protos", "fields", "methods", "code", "data", "strids"
    )
    private const val SEC_BASE = 28

    fun run(ctx: Context, onLog: (String) -> Unit): Boolean {
        val c = IntArray(2)
        onLog("Self-test: VMC structure")
        try {
            body(ctx, onLog, c)
        } catch (t: Throwable) {
            c[1]++
            onLog("  FAIL  threw ${t.javaClass.simpleName}: ${t.message}")
        }
        onLog("SELF-TEST: ${c[0]} passed, ${c[1]} failed")
        return c[1] == 0
    }

    private fun body(ctx: Context, onLog: (String) -> Unit, c: IntArray) {
        val built = String(charArrayOf('a', 'r', 'm', '6', '4', '-', 'v', '8', 'a'))
        check(c, onLog, "const-string equals the same chars built at runtime",
                built == "arm64-v8a", "built='$built'")
        check(c, onLog, "String.hashCode agrees across two sources",
                built.hashCode() == "arm64-v8a".hashCode(),
                "$built=${built.hashCode()} literal=${"arm64-v8a".hashCode()}")
        var sum = 0
        for (i in 1..10) sum += i
        check(c, onLog, "loop arithmetic", sum == 55, "sum=$sum")
        val a0 = AbiPreflight.vmcAssetFor("arm64-v8a")
        val a1 = AbiPreflight.vmcAssetFor("armeabi-v7a")
        val a2 = AbiPreflight.vmcAssetFor("x86")
        val a3 = AbiPreflight.vmcAssetFor("x86_64")
        val a4 = AbiPreflight.vmcAssetFor("mips")
        check(c, onLog, "String-when dispatch maps every ABI correctly",
                a0 == "vmp/libVMP-arm64-v8a.so" &&
                        a1 == "vmp/libVMP-armeabi-v7a.so" &&
                        a2 == "vmp/libVMP-x86.so" &&
                        a3 == "vmp/libVMP-x86_64.so" &&
                        a4 == null,
                "arm64=$a0 armv7=$a1 x86=$a2 x86_64=$a3 mips=$a4")
        var sp = 0
        for (k in intArrayOf(1, 100, 10000)) {
            sp = sp * 100 + when (k) {
                1 -> 11
                100 -> 22
                10000 -> 33
                else -> -1
            }
        }
        check(c, onLog, "sparse-switch on non-contiguous Int keys",
                sp == 112233, "got $sp (always-default would give -10101)")
        var pk = 0
        for (k in 0..2) {
            pk = pk * 10 + when (k) {
                0 -> 7
                1 -> 8
                2 -> 9
                else -> -1
            }
        }
        check(c, onLog, "packed-switch on contiguous Int keys",
                pk == 789, "got $pk")
        val neg = intArrayOf(-1024, -7, -1, 1)
        val negL = longArrayOf(-1049036L, -1L)
        val sh = neg[3]
        val shrInt = neg[0] shr (4 * sh)
        val ushrInt = neg[1] ushr (4 * sh)
        val shrLit = neg[0] shr 3
        val shrLong = negL[0] shr (8 * sh)
        val ushrLong = negL[1] ushr (63 * sh)
        check(c, onLog, "shr propagates the sign while ushr shifts in zeros",
                shrInt == -64 && ushrInt == 268435455 && shrLit == -128 &&
                        shrLong == -4098L && ushrLong == 1L,
                "shrInt=$shrInt ushrInt=$ushrInt shrLit=$shrLit " +
                        "shrLong=$shrLong ushrLong=$ushrLong")
        val probe = arrayOf("", "x")
        val joined = "a" + probe[0] + "b"
        check(c, onLog, "const-string \"\" resolves under the VM",
                probe.size == 2 && probe[0].length == 0 && probe[1] == "x" &&
                        joined == "ab",
                "sizes=${probe.map { it.length }} joined='$joined'")

        val ccKey = ByteArray(32)
        var ccI = 0
        while (ccI < 32) { ccKey[ccI] = ccI.toByte(); ccI++ }
        val ccNonce = byteArrayOf(0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0)
        val ccOut = ByteArray(64)
        ApkBuilder.chacha20Block(ccKey, 1, ccNonce, ccOut)
        val ccExp = intArrayOf(
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e)
        var ccBad = -1
        ccI = 0
        while (ccI < 64) {
            if ((ccOut[ccI].toInt() and 0xff) != ccExp[ccI]) { ccBad = ccI; break }
            ccI++
        }
        val ccHex = StringBuilder()
        ccI = 0
        while (ccI < 64) {
            val b = ccOut[ccI].toInt() and 0xff
            if (b < 16) ccHex.append('0')
            ccHex.append(Integer.toHexString(b))
            ccI++
        }
        check(c, onLog, "ChaCha20 block == RFC 8439 2.3.2 vector", ccBad < 0,
                "first diff at $ccBad; got=$ccHex")
        val ccN = 200
        val ccData = ByteArray(ccN)
        ccI = 0
        while (ccI < ccN) { ccData[ccI] = (ccI and 0xff).toByte(); ccI++ }
        val ccE0 = ApkBuilder.chacha20Transform(ccData, 0, ccKey)
        val ccE1 = ApkBuilder.chacha20Transform(ccData, 1, ccKey)
        var ccAllEq = true
        ccI = 0
        while (ccI < ccN) { if (ccE0[ccI] != ccE1[ccI]) ccAllEq = false; ccI++ }
        check(c, onLog, "per-blob nonce: blobIndex 0 and 1 give different keystream",
                !ccAllEq, "blobs 0 and 1 produced identical ciphertext (reuse)")
        val ccD0 = ApkBuilder.chacha20Transform(ccE0, 0, ccKey)
        var ccRt = true
        ccI = 0
        while (ccI < ccN) { if (ccD0[ccI] != ccData[ccI]) ccRt = false; ccI++ }
        check(c, onLog, "ChaCha20 transform is self-inverse (round-trip)", ccRt,
                "round-trip mismatch")

        val isN = 130
        val isBuf = ByteArray(isN)
        var isi = 0
        while (isi < isN) { isBuf[isi] = (isi and 0xff).toByte(); isi++ }
        val isOrig = isBuf.copyOf()
        val isKey = ByteArray(32)
        isi = 0
        while (isi < 32) { isKey[isi] = (0x10 + isi).toByte(); isi++ }
        val isNonce = ByteArray(12)
        isNonce[0] = 0x44; isNonce[1] = 0x41; isNonce[2] = 0x54; isNonce[3] = 0x41
        isNonce[4] = 0x22.toByte()
        ApkBuilder.chacha20StreamXor(isBuf, 3, isN - 6, isKey, isNonce)
        var isChanged = false
        isi = 3
        while (isi < isN - 3) { if (isBuf[isi] != isOrig[isi]) isChanged = true; isi++ }
        ApkBuilder.chacha20StreamXor(isBuf, 3, isN - 6, isKey, isNonce)
        var isRt = true
        isi = 0
        while (isi < isN) { if (isBuf[isi] != isOrig[isi]) isRt = false; isi++ }
        check(c, onLog, "inner insn stream: transforms and is self-inverse",
                isChanged && isRt, "changed=$isChanged roundTrip=$isRt")

        val apk = File(ctx.applicationInfo.sourceDir)
        val read = ApkUtil.readEntry(apk, "classes.dex")
        check(c, onLog, "own classes.dex readable", read != null, "null from ${apk.name}")
        val bytes = read ?: return

        val parser = DexParser(bytes,
                PackPolicy.derive(null, null, listOf("com/vmp/packer")), SkipLog())
        check(c, onLog, "dex parsed",
                parser.classDefCount() > 0, "classDefCount=${parser.classDefCount()}")

        val vkeys = parser.virtualizableKeys()
        val vmc = VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 5)).build()
        if (vkeys.isEmpty() && vmc.size == HEADER) {
            c[0]++
            onLog("  PASS  own dex fully virtualized -> bare 112-byte header (packed app)")
            onLog("        container checks skipped: nothing left to virtualize")
            return
        }
        check(c, onLog, "whitelist matched methods", vkeys.isNotEmpty(),
                "0 keys for com/vmp/packer")
        check(c, onLog, "vmc built", vmc.size > HEADER, "size=${vmc.size}")
        if (vmc.size <= HEADER) return

        check(c, onLog, "magic VMP2",
                vmc[0] == 86.toByte() && vmc[1] == 77.toByte() &&
                        vmc[2] == 80.toByte() && vmc[3] == 50.toByte(),
                "first word = 0x${Integer.toHexString(i32(vmc, 0))}")
        check(c, onLog, "version is 1 or 2",
                i32(vmc, 4) == 1 || i32(vmc, 4) == 2, "version=${i32(vmc, 4)}")
        check(c, onLog, "header_size 112", i32(vmc, 12) == HEADER, "=${i32(vmc, 12)}")
        check(c, onLog, "endian tag 0x12345678", i32(vmc, 16) == 0x12345678,
                "=${Integer.toHexString(i32(vmc, 16))}")
        check(c, onLog, "file_size patched to the real length",
                i32(vmc, 8) == vmc.size,
                "header says ${i32(vmc, 8)}, array is ${vmc.size}")

        val sizes = IntArray(8)
        val offs = IntArray(8)
        for (i in 0 until 8) {
            sizes[i] = i32(vmc, SEC_BASE + i * 8)
            offs[i] = i32(vmc, SEC_BASE + i * 8 + 4)
        }
        var inBounds = true
        for (i in 0 until 8) {
            if (sizes[i] < 0 || offs[i] < HEADER ||
                    offs[i].toLong() + sizes[i].toLong() > vmc.size.toLong()) {
                inBounds = false
            }
        }
        check(c, onLog, "every section lies inside [112, file_size)", inBounds,
                "a section is out of bounds")

        val order = (0 until 8).filter { sizes[it] > 0 }.sortedBy { offs[it] }
        var overlap = ""
        for (i in 1 until order.size) {
            val prev = order[i - 1]
            val cur = order[i]
            if (offs[cur] < offs[prev] + sizes[prev]) {
                overlap = "${SEC_NAMES[cur]} starts inside ${SEC_NAMES[prev]}"
            }
        }
        check(c, onLog, "sections do not overlap", overlap.isEmpty(), overlap)

        val strSize = sizes[0]
        val typesOff = offs[1]
        val protosOff = offs[2]
        val fieldsOff = offs[3]
        val methodsOff = offs[4]

        val features = i32(vmc, 20)
        val sparseDesc = features and VmcWriter.FEATURE_SPARSE_DESCRIPTORS != 0

        /** Record offset (absolute into [vmc]) for dex id [id], or -1. */
        fun descRec(secOff: Int, secSize: Int, stride: Int, id: Int): Int {
            if (secSize <= 0 || id < 0) return -1
            if (!sparseDesc) {
                if (id.toLong() * stride + stride > secSize) return -1
                return secOff + id * stride
            }
            val n = i32(vmc, secOff)
            val indexSize = 4 + n * 8
            if (n < 0 || indexSize > secSize) return -1
            var lo = 0
            var hi = n
            while (lo < hi) {
                val mid = lo + (hi - lo) / 2
                val e = secOff + 4 + mid * 8
                val key = i32(vmc, e)
                if (key == id) {
                    val rec = i32(vmc, e + 4)
                    if (rec < indexSize || rec.toLong() + stride > secSize) return -1
                    return secOff + rec
                }
                if (key < id) lo = mid + 1 else hi = mid
            }
            return -1
        }

        fun typeStrOff(i: Int): Int = descRec(typesOff, sizes[1], 4, i).let { if (it < 0) 0 else i32(vmc, it) }
        fun methodRec(i: Int): Int = descRec(methodsOff, sizes[4], 8, i)
        fun fieldRec(i: Int): Int = descRec(fieldsOff, sizes[3], 8, i)
        fun protoRec(i: Int): Int = descRec(protosOff, sizes[2], 12, i)

        if (sparseDesc) {
            var unsorted = 0
            var outside = 0
            for (t in listOf(Triple(typesOff, sizes[1], 4),
                    Triple(fieldsOff, sizes[3], 8),
                    Triple(methodsOff, sizes[4], 8))) {
                val n = i32(vmc, t.first)
                val indexSize = 4 + n * 8
                var prev = -1
                for (k in 0 until n) {
                    val e = t.first + 4 + k * 8
                    val id = i32(vmc, e)
                    val rec = i32(vmc, e + 4)
                    if (id <= prev) unsorted++
                    prev = id
                    if (indexSize > t.second || rec < indexSize ||
                            rec + t.third > t.second) outside++
                }
            }
            check(c, onLog, "sparse descriptor tables are sorted and in range",
                    unsorted == 0 && outside == 0,
                    "$unsorted out-of-order ids, $outside records outside the section")
        }

        var bad = 0
        for (i in 0 until parser.typeCount()) {
            if (typeStrOff(i) >= strSize) bad++
        }
        for (i in 0 until parser.methodCount()) {
            val r = methodRec(i)
            if (r >= 0 && i32(vmc, r + 4) >= strSize) bad++
        }
        for (i in 0 until parser.fieldCount()) {
            val r = fieldRec(i)
            if (r >= 0 && i32(vmc, r + 4) >= strSize) bad++
        }
        check(c, onLog, "type/method/field string offsets are inside the blob",
                bad == 0, "$bad offsets point past the string section")

        val pSize = sizes[2]
        var pos = 0
        var walked = 0
        if (sparseDesc) {
            val pn = i32(vmc, protosOff)
            pos = 4 + pn * 8
            while (pos + 4 <= pSize && walked < pn) {
                val pc = i32(vmc, protosOff + pos)
                pos += 4 + pc * 4 + 8
                walked++
            }
            check(c, onLog, "sparse proto table walks exactly to its end",
                    pos == pSize && walked == pn && pn in 1..parser.protoCount(),
                    "pos=$pos size=$pSize walked=$walked of $pn (dex has ${parser.protoCount()})")
        } else {
            while (pos + 4 <= pSize && walked < parser.protoCount()) {
                val pc = i32(vmc, protosOff + pos)
                pos += 4 + pc * 4 + 8
                walked++
            }
            check(c, onLog, "proto table walks exactly to its end",
                    pos == pSize && walked == parser.protoCount(),
                    "pos=$pos size=$pSize walked=$walked of ${parser.protoCount()}")
        }

        check(c, onLog, "string blob ends on a NUL",
                strSize > 0 && vmc[offs[0] + strSize - 1] == 0.toByte(),
                "last byte is not 0 (MUTF-8 blob is unterminated)")

        val codeSize = sizes[5]
        val codeOff = offs[5]
        check(c, onLog, "code table is a whole number of records",
                codeSize % 36 == 0, "size=$codeSize")
        val codeCount = codeSize / 36
        check(c, onLog, "code count does not exceed the candidate count",
                codeCount <= vkeys.size, "$codeCount > ${vkeys.size}")
        val dataSize = sizes[6]
        var badInsn = 0
        for (i in 0 until codeCount) {
            val base = codeOff + i * 36
            val insnsSize = i32(vmc, base + 20)
            val insnsOff = i32(vmc, base + 24)
            if (insnsOff < 0 ||
                    insnsOff.toLong() + insnsSize.toLong() * 2L > dataSize.toLong()) {
                badInsn++
            }
        }
        check(c, onLog, "every method's instruction range fits the data section",
                badInsn == 0, "$badInsn entries run past the data section")

        val strOff = offs[0]
        val stridsOff = offs[7]
        val vmcVersion = i32(vmc, 4)

        check(c, onLog, "string blob offset 0 is the empty-string sentinel",
                strSize > 0 && vmc[strOff] == 0.toByte(),
                "first byte is ${vmc[strOff].toInt() and 0xff}, not NUL - a pruned " +
                        "lookup would resolve to a real string")

        var blobStrings = 0
        var bp = 1
        while (bp < strSize) {
            if (vmc[strOff + bp] == 0.toByte()) blobStrings++
            bp++
        }

        if (vmcVersion >= 2) {
            val n = i32(vmc, stridsOff)
            check(c, onLog, "sparse string-id table fits its section",
                    sizes[7] == 4 + n * 8, "count=$n section=${sizes[7]}")
            var unsorted = 0
            var badEntry = 0
            var dupIdx = 0
            var dupOff = 0
            var prev = -1
            val seenIdx = HashSet<Int>()
            val seenOff = HashSet<Int>()
            for (i in 0 until n) {
                val idx = i32(vmc, stridsOff + 4 + i * 8)
                val o = i32(vmc, stridsOff + 4 + i * 8 + 4)
                if (idx <= prev) unsorted++
                prev = idx
                if (idx < 0 || idx >= parser.stringCount()) badEntry++
                if (!strResolves(vmc, strOff, strSize, o)) badEntry++
                if (o == 0 && parser.stringByIdx(idx) != "") badEntry++
                if (!seenIdx.add(idx)) dupIdx++
                if (!seenOff.add(o)) dupOff++
            }
            check(c, onLog, "sparse string-id table is sorted by index",
                    unsorted == 0, "$unsorted out-of-order entries")
            check(c, onLog, "every sparse string-id resolves to a real string",
                    badEntry == 0, "$badEntry bad entries")
            check(c, onLog, "no duplicate string-id entries",
                    dupIdx == 0, "$dupIdx duplicates")
            check(c, onLog, "sparse string-id entries are a subset of the blob",
                    n <= blobStrings, "$n entries vs $blobStrings blob strings")
            check(c, onLog, "no two sparse entries share a blob offset",
                    dupOff == 0, "$dupOff shared offsets")
            onLog("        prune: $n of ${parser.stringCount()} string-ids kept " +
                    "(${sizes[7]} bytes vs ${parser.stringCount() * 4} dense)")
        } else {
            val nStrIds = sizes[7] / 4
            check(c, onLog, "string-id table covers every dex string_id",
                    nStrIds == parser.stringCount(),
                    "table has $nStrIds entries, dex has ${parser.stringCount()}")
            var dangling = 0
            for (i in 0 until nStrIds) {
                val o = i32(vmc, stridsOff + i * 4)
                if (!strResolves(vmc, strOff, strSize, o)) dangling++
            }
            check(c, onLog, "every string-id resolves to a real NUL-terminated string",
                    dangling == 0, "$dangling of $nStrIds point at nothing")
            var sentinelIds = 0
            val liveTargets = HashSet<Int>()
            var dupTargets = 0
            for (i in 0 until nStrIds) {
                val o = i32(vmc, stridsOff + i * 4)
                if (o == 0) { sentinelIds++; continue }
                if (!liveTargets.add(o)) dupTargets++
            }
            check(c, onLog, "no two LIVE string-ids share a target (catches the ?: 0 fallback)",
                    dupTargets == 0, "$dupTargets duplicate non-sentinel targets")
            onLog("        prune: $sentinelIds of $nStrIds string-ids point at the sentinel")
        }

        var badRef = 0
        for (i in 0 until parser.typeCount()) {
            if (!strResolves(vmc, strOff, strSize, typeStrOff(i))) badRef++
        }
        for (i in 0 until parser.methodCount()) {
            val r = methodRec(i)
            if (r >= 0 && !strResolves(vmc, strOff, strSize, i32(vmc, r + 4))) badRef++
        }
        for (i in 0 until parser.fieldCount()) {
            val r = fieldRec(i)
            if (r >= 0 && !strResolves(vmc, strOff, strSize, i32(vmc, r + 4))) badRef++
        }
        if (sparseDesc) {
            for (i in 0 until parser.protoCount()) {
                val pr = protoRec(i)
                if (pr < 0) continue
                val pc = i32(vmc, pr)
                for (k in 0 until pc) {
                    if (!strResolves(vmc, strOff, strSize,
                            i32(vmc, pr + 4 + k * 4))) badRef++
                }
                if (!strResolves(vmc, strOff, strSize,
                        i32(vmc, pr + 4 + pc * 4))) badRef++
                if (!strResolves(vmc, strOff, strSize,
                        i32(vmc, pr + 4 + pc * 4 + 4))) badRef++
            }
        } else {
            var pp = 0
            var pn = 0
            while (pp + 4 <= pSize && pn < parser.protoCount()) {
                val pc = i32(vmc, protosOff + pp)
                for (k in 0 until pc) {
                    if (!strResolves(vmc, strOff, strSize,
                                    i32(vmc, protosOff + pp + 4 + k * 4))) badRef++
                }
                if (!strResolves(vmc, strOff, strSize,
                                i32(vmc, protosOff + pp + 4 + pc * 4))) badRef++
                if (!strResolves(vmc, strOff, strSize,
                                i32(vmc, protosOff + pp + 4 + pc * 4 + 4))) badRef++
                pp += 4 + pc * 4 + 8
                pn++
            }
        }
        check(c, onLog, "every type/method/field/proto string reference resolves",
                badRef == 0, "$badRef references point at nothing")

        var unresolvable = 0
        for (i in 0 until codeCount) {
            val base = codeOff + i * 36
            val midx = i32(vmc, base)
            if (midx < 0 || midx >= parser.methodCount()) { unresolvable++; continue }
            val mEntry = methodRec(midx)
            if (mEntry < 0) {
                unresolvable++
            } else {
                val clsIdx = i32(vmc, mEntry) and 0xffff
                val protoIdx = i32(vmc, mEntry + 2) and 0xffff
                if (i32(vmc, mEntry + 4) == 0) unresolvable++
                if (clsIdx < parser.typeCount() &&
                        typeStrOff(clsIdx) == 0) unresolvable++
                val q = if (sparseDesc) protoRec(protoIdx) - protosOff
                else {
                    var w = 0
                    for (p in 0 until protoIdx) {
                        if (w + 4 > pSize) break
                        w += 4 + i32(vmc, protosOff + w) * 4 + 8
                    }
                    w
                }
                var sigOk = false
                if (q in 0 until pSize - 11) {
                    val pc = i32(vmc, protosOff + q)
                    sigOk = i32(vmc, protosOff + q + 4 + pc * 4) != 0 &&
                            i32(vmc, protosOff + q + 4 + pc * 4 + 4) != 0
                }
                if (!sigOk) unresolvable++
            }
        }
        check(c, onLog, "every virtualized method resolves name/class/signature",
                unresolvable == 0,
                "$unresolvable of $codeCount virtualized methods have a sentinel " +
                        "name/class/signature - the reachability walk under-included")

        var badCatchType = 0
        val selfDexFile = com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile(
                com.android.tools.smali.dexlib2.Opcodes.forApi(34), parser.rawBytes())
        val vsetForCatch = vkeys.toHashSet()
        for (classDef in selfDexFile.classes) {
            for (method in classDef.methods) {
                val impl = method.implementation ?: continue
                val key = "${method.definingClass}|${method.name}|" +
                        method.parameters.joinToString("") { it.type } + "|" +
                        method.returnType
                if (key !in vsetForCatch) continue
                for (tb in impl.tryBlocks) {
                    for (eh in tb.exceptionHandlers) {
                        val exType = eh.exceptionType ?: continue
                        for (ti in 0 until parser.typeCount()) {
                            if (parser.typeDesc(ti) == exType) {
                                if (typeStrOff(ti) == 0) badCatchType++
                                break
                            }
                        }
                    }
                }
            }
        }
        check(c, onLog, "no catch-handler type resolves to the empty-string sentinel",
                badCatchType == 0,
                "$badCatchType catch-handler types were pruned - caught exceptions " +
                        "will escape as uncaught")

        val dense = VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 1)).build()
        var denseOk = dense.size > HEADER
        var denseInfo = "size=${dense.size}"
        if (denseOk) {
            val dVersion = i32(dense, 4)
            val dStrIds = i32(dense, SEC_BASE + 7 * 8)
            denseOk = dVersion == 1 && dStrIds == parser.stringCount() * 4
            denseInfo = "version=$dVersion strIds=$dStrIds expected=${parser.stringCount() * 4}"
        }
        check(c, onLog, "dense path (cap=1) emits a v1 full-length string-id table",
                denseOk, denseInfo)
        val denseDesc =
                VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 4)).build()
        val sparseDescVmc =
                VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 5)).build()
        check(c, onLog, "sparse descriptors shrink the container on a real dex",
                sparseDescVmc.size < denseDesc.size,
                "sparse=${sparseDescVmc.size} vs dense=${denseDesc.size}")

        val noMatch = DexParser(bytes,
                PackPolicy.derive(null, null, listOf("zzz/not/a/real/package")), SkipLog())
        val empty = VmcWriter(noMatch, PackConfig(runtimeMaxContainerVersion = 5)).build()
        var zeroed = empty.size == HEADER
        if (zeroed) {
            for (i in 0 until 8) {
                if (i32(empty, SEC_BASE + i * 8) != 0 ||
                        i32(empty, SEC_BASE + i * 8 + 4) != 0) zeroed = false
            }
        }
        check(c, onLog, "empty dex yields a 112-byte zero-descriptor header", zeroed,
                "size=${empty.size} (the empty-container path regressed?)")

        val ex = PackPolicy.derive(null, null,
                listOf("com/vmp/packer", "!com/vmp/packer/SelfTest")).activeExcludes
        check(c, onLog, "class-level exclusion reaches the policy",
                ex.contains("Lcom/vmp/packer/SelfTest"), "activeExcludes=$ex")

        var permBlob: ByteArray? = null
        var permErr = ""
        try {
            val w = VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 4))
            w.insnStarts = InsnPerm.collectStarts(bytes, vkeys) { parser.insnsSizeOf(it) }
            permBlob = w.build()
        } catch (t: Throwable) {
            permErr = "${t.javaClass.simpleName}: ${t.message}"
        }
        val pv = permBlob
        val pOff = if (pv != null) i32(pv, InsnPerm.PERM_OFF_SLOT) else 0
        check(c, onLog, "perm: walk covers every virtualized method",
                pv != null && pOff >= 112 && i32(pv, 8) == pv.size,
                if (permErr.isNotEmpty()) permErr else "perm_off=$pOff")
        if (pv != null && pOff >= 112) {
            val before = pv.copyOf()
            val fwd = InsnPerm.applyToBlob(pv, s2c = false)
            val changed = !pv.contentEquals(before)
            val back = InsnPerm.applyToBlob(pv, s2c = true)
            check(c, onLog, "perm: apply transforms opcode bytes", fwd && changed,
                    "applied=$fwd changed=$changed")
            check(c, onLog, "perm: round-trip is byte-exact", back && pv.contentEquals(before),
                    "restored=$back")
        }

        var mpErr = ""
        val mp = try {
            val w2 = VmcWriter(parser,
                    PackConfig(runtimeMaxContainerVersion = InsnPerm.MULTI_PERM_CAP))
            w2.insnStarts = InsnPerm.collectStarts(bytes, vkeys) { parser.insnsSizeOf(it) }
            w2.build()
        } catch (t: Throwable) {
            mpErr = "${t.javaClass.simpleName}: ${t.message}"; null
        }
        val mpOff = if (mp != null) i32(mp, InsnPerm.PERM_OFF_SLOT) else 0
        check(c, onLog, "perm v7: multi-LUT section emitted",
                mp != null && mpOff >= 112 && i32(mp, 8) == mp.size,
                if (mpErr.isNotEmpty()) mpErr else "perm_off=$mpOff")
        if (mp != null && mpOff >= 112) {
            val before2 = mp.copyOf()
            val fwd2 = InsnPerm.applyToBlob(mp, s2c = false, multi = true)
            val changed2 = !mp.contentEquals(before2)
            val back2 = InsnPerm.applyToBlob(mp, s2c = true, multi = true)
            check(c, onLog, "perm v7: apply transforms opcode bytes", fwd2 && changed2,
                    "applied=$fwd2 changed=$changed2")
            check(c, onLog, "perm v7: round-trip is byte-exact",
                    back2 && mp.contentEquals(before2), "restored=$back2")
        }

        var irBlob: ByteArray? = null
        var irErr = ""
        try {
            val w3 = VmcWriter(parser,
                    PackConfig(runtimeMaxContainerVersion = IrCodec.IR_FUSE2_CAP))
            w3.insnStarts = InsnPerm.collectStarts(bytes, vkeys) { parser.insnsSizeOf(it) }
            w3.insnTargets = InsnPerm.collectTargets(bytes, vkeys) { parser.insnsSizeOf(it) }
            w3.onPermSkip = { msg -> onLog("  info  $msg") }
            irBlob = w3.build()
        } catch (t: Throwable) {
            irErr = "${t.javaClass.simpleName}: ${t.message}"
        }
        val irb = irBlob
        check(c, onLog, "ir v1: cap-8 container builds", irb != null, irErr)
        if (irb != null) {
            fun u16at(o: Int) = (irb[o].toInt() and 0xff) or ((irb[o + 1].toInt() and 0xff) shl 8)
            val irOff = i32(irb, 96)
            val codeOff2 = i32(irb, 72)
            val nrec = i32(irb, 68) / 36
            val dataOff2 = i32(irb, 80)
            check(c, onLog, "ir v1: IR section emitted, blob still version 2 pre-encrypt",
                    irOff >= 112 && i32(irb, 4) == 2 && i32(irb, irOff) == nrec,
                    "ir_off=$irOff nrec=$nrec")
            val fusedTotal = i32(irb, irOff + 4 + 4 * nrec)
            onLog("  INFO  ir v2: fusedTotal=$fusedTotal")
            if (fusedTotal == 0) onLog("  WARN  ir v2: no fused patterns in the fixture")
            var irN = 0
            var badRec = ""
            for (r in 0 until nrec) {
                val rec = codeOff2 + r * 36
                if (i32(irb, rec + 4) and 0x10000000 == 0) continue
                irN++
                val tab = i32(irb, irOff + 4 + 4 * r)
                if (tab < 4 + 4 * nrec || tab + 2 > i32(irb, 100)) { badRec = "tab r=$r tab=$tab"; break }
                val cnt = u16at(irOff + tab)
                if (cnt < 1 || tab + 2 + 2 * cnt + 32 > i32(irb, 100)) {
                    badRec = "cnt r=$r cnt=$cnt irSize=${i32(irb, 100)}"; break }
                val widths = IntArray(cnt) { u16at(irOff + tab + 2 + 2 * it) }
                if (widths.any { it < 1 || it > 8 }) {
                    badRec = "width r=$r w0=${widths.firstOrNull()}"; break }
                val rs = dataOff2 + i32(irb, rec + 24)
                if (rs < 0 || rs + cnt * 16 > irb.size) { badRec = "region r=$r"; break }
                val back = IrCodec.decode(irb.copyOfRange(rs, rs + cnt * 16), widths)
                if (back == null) { badRec = "decode r=$r"; break }
                run {
                    val permOff2 = i32(irb, 92)
                    val lutArea2 = InsnPerm.PERM_LUT_COUNT * InsnPerm.LUT_SIZE
                    if (permOff2 < 112) { badRec = "unperm r=$r (no perm)"; return@run }
                    val rel2 = i32(irb, permOff2 + lutArea2 + nrec + 4 * r)
                    val sc = u16at(permOff2 + rel2)
                    val selByte = irb[permOff2 + lutArea2 + r].toInt() and 0xff
                    if (sc < 1 || selByte >= InsnPerm.PERM_LUT_COUNT) {
                        badRec = "unperm r=$r (sc=$sc sel=$selByte)"; return@run
                    }
                    val lb = permOff2 + selByte * 256
                    for (j in 0 until sc) {
                        val pos2 = 2 * u16at(permOff2 + rel2 + 2 + 2 * j)
                        if (pos2 < back.size)
                            back[pos2] = irb[lb + (back[pos2].toInt() and 0xff)]
                    }
                }
                if (badRec.isNotEmpty()) break
                val stored = irb.copyOfRange(irOff + tab + 2 + 2 * cnt, irOff + tab + 2 + 2 * cnt + 32)
                val sha = java.security.MessageDigest.getInstance("SHA-256").digest(back)
                val shaOk = stored.contentEquals(sha)
                val units = widths.sum()
                if (units != i32(irb, rec + 20)) {
                    var elsewhere = "no"
                    val wantSize = i32(irb, rec + 20)
                    for (q in 0 until nrec) {
                        val tq = i32(irb, irOff + 4 + 4 * q)
                        if (tq < 4 + 4 * nrec || tq + 2 > i32(irb, 100)) continue
                        val cq = u16at(irOff + tq)
                        if (cq < 1 || tq + 2 + 2 * cq + 32 > i32(irb, 100)) continue
                        var sq = 0; var okq = true
                        for (j in 0 until cq) {
                            val wj = u16at(irOff + tq + 2 + 2 * j)
                            if (wj < 1 || wj > 8) { okq = false; break }
                            sq += wj
                        }
                        if (okq && sq == wantSize) { elsewhere = "yes(q=$q)"; break }
                    }
                    badRec = "sum r=$r units=$units size=$wantSize " +
                            "cnt=$cnt midx=${i32(irb, rec)} " +
                            "sha=" + (if (shaOk) "ok" else "no") +
                            " elsewhere=$elsewhere"; break }
                if (!shaOk) { badRec = "sha r=$r"; break }
            }
            check(c, onLog, "ir v1: IR methods exist at cap 8", irN >= 1, "irN=0")
            check(c, onLog, "ir v1: every IR region decodes + hashes exact",
                    badRec.isEmpty(), badRec)
            val before3 = irb.copyOf()
            val f3 = InsnPerm.applyToBlob(irb, s2c = false, multi = true)
            val b3 = InsnPerm.applyToBlob(irb, s2c = true, multi = true)
            check(c, onLog, "ir v1: perm round-trips with IR records skipped",
                    f3 && b3 && irb.contentEquals(before3), "fwd=$f3 back=$b3")
        }

        run {
            val irStarts = InsnPerm.collectStarts(bytes, vkeys) { parser.insnsSizeOf(it) }
            var irOk = 0
            var irTried = 0
            var irErr = ""
            for ((key, st) in irStarts) {
                val code = parser.codeOf(key) ?: continue
                irTried++
                try {
                    if (IrCodec.encode(code.insns, st, code.insnsSize) != null) irOk++
                } catch (t: Throwable) {
                    if (irErr.isEmpty()) irErr = "$key: ${t.javaClass.simpleName}: ${t.message}"
                }
            }
            check(c, onLog, "ir v0: encode() never throws", irErr.isEmpty(), irErr)
            check(c, onLog, "ir v0: round-trip-verified methods exist",
                    irOk >= 1, "ok=$irOk tried=$irTried (all fell back?)")
            onLog("  INFO  ir v0 coverage: $irOk/$irTried fixture methods IR-encode")
        }
    }

    private fun check(
        c: IntArray,
        onLog: (String) -> Unit,
        name: String,
        cond: Boolean,
        detail: String
    ) {
        if (cond) {
            c[0]++
            onLog("  PASS  $name")
        } else {
            c[1]++
            onLog("  FAIL  $name - $detail")
        }
    }

    /**
     * True when [off] is a string offset that reaches a NUL before the section
     * ends. Empty strings count as valid (offset 0 is the sentinel).
     */
    private fun strResolves(b: ByteArray, strOff: Int, strSize: Int, off: Int): Boolean {
        if (off < 0 || off >= strSize) return false
        var i = strOff + off
        val end = strOff + strSize
        while (i < end) {
            if (b[i] == 0.toByte()) return true
            i++
        }
        return false
    }

    /** Little-endian u32, matching VmcWriter's ByteBuffer order. */
    private fun i32(b: ByteArray, off: Int): Int {
        if (off < 0 || off + 4 > b.size) return -1
        return (b[off].toInt() and 0xff) or
                ((b[off + 1].toInt() and 0xff) shl 8) or
                ((b[off + 2].toInt() and 0xff) shl 16) or
                ((b[off + 3].toInt() and 0xff) shl 24)
    }
}
