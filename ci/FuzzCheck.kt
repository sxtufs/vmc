import com.vmp.packer.AxmlPatcher
import com.vmp.packer.DexParser
import com.vmp.packer.InsnPerm
import com.vmp.packer.PackConfig
import com.vmp.packer.PackPolicy
import com.vmp.packer.SkipLog
import com.vmp.packer.VmcWriter
import java.io.File

/**
 * Deterministic JVM mutation lane for the pure packer boundary.
 *
 * Native VMP2 parsing is covered by libFuzzer in native/fuzz. This lane covers
 * the Kotlin-side DEX/AXML readers and VMC writer with the same bounded,
 * malformed-input mindset: mutations may be rejected, but they must not crash
 * the process or produce an invalid successful VMC.
 */
private class Rng(seed: Long) {
    private var state = seed

    fun nextInt(bound: Int): Int {
        require(bound > 0)
        state = state * 6364136223846793005L + 1442695040888963407L
        return ((state ushr 33) % bound.toLong()).toInt()
    }
}

private fun mutate(seed: ByteArray, iteration: Int): ByteArray {
    val out = seed.copyOf()
    val rng = Rng(0x564D50464C5A0000L xor iteration.toLong())
    repeat(1 + rng.nextInt(8)) {
        val at = rng.nextInt(out.size)
        val mask = 1 + rng.nextInt(255)
        out[at] = (out[at].toInt() xor mask).toByte()
    }
    return out
}

private fun put16(out: ByteArray, offset: Int, value: Int) {
    out[offset] = value.toByte()
    out[offset + 1] = (value ushr 8).toByte()
}

private fun put32(out: ByteArray, offset: Int, value: Int) {
    for (i in 0 until 4) out[offset + i] = (value ushr (8 * i)).toByte()
}

private fun align4(value: Int): Int = (value + 3) and -4

/** A small structurally valid string-pool plus a zero-attribute manifest node. */
private fun axmlSeed(): ByteArray {
    val strings = listOf(
        "manifest",
        "application",
        "package",
        "http://schemas.android.com/apk/res/android"
    )
    val encoded = ArrayList<Byte>()
    val offsets = ArrayList<Int>()
    for (value in strings) {
        offsets += encoded.size
        val bytes = value.toByteArray(Charsets.UTF_8)
        encoded += value.length.toByte()
        encoded += bytes.size.toByte()
        encoded += bytes.toList()
        encoded += 0.toByte()
    }

    val poolHeaderSize = 28
    val stringDataStart = poolHeaderSize + strings.size * 4
    val poolSize = align4(stringDataStart + encoded.size)
    val elementSize = 36
    val fileSize = 8 + poolSize + elementSize
    val out = ByteArray(fileSize)

    put16(out, 0, 0x0003)
    put16(out, 2, 8)
    put32(out, 4, fileSize)

    val pool = 8
    put16(out, pool, 0x0001)
    put16(out, pool + 2, poolHeaderSize)
    put32(out, pool + 4, poolSize)
    put32(out, pool + 8, strings.size)
    put32(out, pool + 12, 0)
    put32(out, pool + 16, 0x00000100)
    put32(out, pool + 20, stringDataStart)
    put32(out, pool + 24, 0)
    offsets.forEachIndexed { index, offset ->
        put32(out, pool + poolHeaderSize + index * 4, offset)
    }
    encoded.forEachIndexed { index, byte ->
        out[pool + stringDataStart + index] = byte.toByte()
    }

    val element = pool + poolSize
    put16(out, element, 0x0102)
    put16(out, element + 2, 16)
    put32(out, element + 4, elementSize)
    put32(out, element + 8, 1)
    put32(out, element + 12, -1)
    put32(out, element + 16, -1)
    put32(out, element + 20, 0)
    put16(out, element + 24, 20)
    put16(out, element + 26, 20)
    put16(out, element + 28, 0)
    put16(out, element + 30, 0)
    put16(out, element + 32, 0)
    put16(out, element + 34, 0)
    return out
}

private fun requireHeader(vmc: ByteArray) {
    check(vmc.size >= 112) { "VMC output is shorter than its header" }
    check(vmc[0] == 'V'.code.toByte() && vmc[1] == 'M'.code.toByte() &&
            vmc[2] == 'P'.code.toByte() && vmc[3] == '2'.code.toByte()) {
        "VMC output has the wrong magic"
    }
    val declaredSize = (vmc[8].toInt() and 0xff) or
            ((vmc[9].toInt() and 0xff) shl 8) or
            ((vmc[10].toInt() and 0xff) shl 16) or
            ((vmc[11].toInt() and 0xff) shl 24)
    check(declaredSize == vmc.size) { "VMC size field disagrees with output length" }
}

fun main(args: Array<String>) {
    val fixture = File(args.singleOrNull() ?: error("usage: FuzzCheck <classes.dex>"))
    val dexSeed = fixture.readBytes()
    require(dexSeed.isNotEmpty()) { "empty DEX fixture" }

    val policy = PackPolicy.derive(null, null, listOf("fixt"))
    var dexAccepted = 0
    var vmcBuilt = 0
    var dexRejected = 0

    repeat(1000) { iteration ->
        val mutated = if (iteration == 0) dexSeed else mutate(dexSeed, iteration)
        try {
            val parser = DexParser(mutated, policy, SkipLog())
            dexAccepted++
            if (iteration % 2 == 0) {
                val keys = parser.virtualizableKeys()
                if (keys.isNotEmpty()) {
                    val starts = InsnPerm.collectStarts(mutated, keys) {
                        parser.insnsSizeOf(it)
                    }
                    val writer = VmcWriter(
                        parser,
                        PackConfig(runtimeMaxContainerVersion = 4)
                    )
                    writer.insnStarts = starts
                    requireHeader(writer.build())
                    vmcBuilt++
                }
            }
        } catch (_: Exception) {
            dexRejected++
        }
    }

    val axmlSeed = axmlSeed()
    var axmlAccepted = 0
    var axmlRejected = 0
    repeat(1000) { iteration ->
        val mutated = if (iteration == 0) axmlSeed else mutate(axmlSeed, iteration)
        try {
            AxmlPatcher.readTargets(mutated)
            axmlAccepted++
        } catch (_: Exception) {
            axmlRejected++
        }
    }

    check(dexAccepted > 0) { "the valid DEX seed was rejected" }
    check(vmcBuilt > 0) { "no accepted DEX mutation reached VMC generation" }
    check(axmlAccepted > 0) { "the valid AXML seed was rejected" }
    check(dexRejected > 0) { "DEX mutation lane did not reject any malformed input" }
    check(axmlRejected > 0) { "AXML mutation lane did not reject any malformed input" }

    println("FUZZ CHECK: dex accepted=$dexAccepted rejected=$dexRejected")
    println("FUZZ CHECK: vmc built=$vmcBuilt")
    println("FUZZ CHECK: axml accepted=$axmlAccepted rejected=$axmlRejected")
}
