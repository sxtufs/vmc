package com.vmp.packer

import java.security.MessageDigest
import java.util.zip.Adler32

/** Final DEX invariant repair for method flags emitted by the serializer. */
object DexPostProcessor {
    private const val ACC_NATIVE = 0x100
    private const val ACC_ABSTRACT = 0x400
    private const val MAP_OFF = 0x34
    private const val MAP_CODE_ITEM = 0x2001

    /**
     * Native and abstract methods must have code_off == 0. Some dexlib2 writer
     * paths can leave the old code_item offset attached when a method changes
     * from a concrete implementation to native. Clear only those offsets, keep
     * the ULEB width stable, then refresh the DEX signature and checksum.
     */
    fun repairCodeItems(input: ByteArray, onRepair: (String) -> Unit = {}): ByteArray {
        val dex = input.copyOf()
        require(dex.size >= 0x70) { "DEX is smaller than its header" }
        val classCount = u32(dex, 0x60)
        val classDefsOff = u32(dex, 0x64)
        require(classCount >= 0 && classDefsOff >= 0 &&
                classDefsOff.toLong() + classCount.toLong() * 32L <= dex.size) {
            "DEX class_defs table is outside the file"
        }

        var clearedNative = 0
        var raisedFrames = 0
        repeat(classCount) { classIndex ->
            val classDef = classDefsOff + classIndex * 32
            val classDataOff = u32(dex, classDef + 24)
            if (classDataOff == 0) return@repeat
            var cursor = classDataOff
            val staticFields = readUleb(dex, cursor).also { cursor = it.next }
            val instanceFields = readUleb(dex, cursor).also { cursor = it.next }
            val directMethods = readUleb(dex, cursor).also { cursor = it.next }
            val virtualMethods = readUleb(dex, cursor).also { cursor = it.next }

            repeat(staticFields.value + instanceFields.value) {
                cursor = readUleb(dex, cursor).next
                cursor = readUleb(dex, cursor).next
            }
            repeat(directMethods.value + virtualMethods.value) {
                cursor = readUleb(dex, cursor).next
                val access = readUleb(dex, cursor).also { cursor = it.next }
                val code = readUleb(dex, cursor)
                cursor = code.next
                if (code.value != 0 &&
                        (access.value and (ACC_NATIVE or ACC_ABSTRACT)) != 0) {
                    for (p in code.start until code.next - 1) dex[p] = 0x80.toByte()
                    dex[code.next - 1] = 0
                    clearedNative++
                } else if (code.value != 0) {
                    val codeOff = code.value
                    require(codeOff >= 0 && codeOff <= dex.size - 6) {
                        "code_item offset $codeOff is outside the DEX"
                    }
                    val registers = readU16(dex, codeOff)
                    val ins = readU16(dex, codeOff + 2)
                    if (ins > registers) {
                        putU16(dex, codeOff, ins)
                        raisedFrames++
                    }
                }
            }
        }

        val mapOff = u32(dex, MAP_OFF)
        if (mapOff != 0 && mapOff >= 0 && mapOff <= dex.size - 4) {
            var mapCursor = mapOff + 4
            val mapCount = u32(dex, mapOff)
            require(mapCount >= 0 && mapCursor.toLong() + mapCount.toLong() * 12L <= dex.size) {
                "DEX map_list is outside the file"
            }
            repeat(mapCount) {
                val type = readU16(dex, mapCursor)
                val size = u32(dex, mapCursor + 4)
                val offset = u32(dex, mapCursor + 8)
                mapCursor += 12
                if (type == MAP_CODE_ITEM && size > 0 && offset >= 0) {
                    raisedFrames += repairCodeSection(dex, offset, size)
                }
            }
        }

        if (clearedNative == 0 && raisedFrames == 0) return dex
        onRepair("DEX post-processor: cleared code_off for $clearedNative " +
                "native/abstract method(s), raised registers_size for $raisedFrames method(s)")
        refreshDexIntegrity(dex)
        return dex
    }

    private data class Uleb(val value: Int, val start: Int, val next: Int)

    private fun readUleb(bytes: ByteArray, offset: Int): Uleb {
        require(offset in bytes.indices) { "ULEB offset outside DEX" }
        var value = 0
        var shift = 0
        var cursor = offset
        while (true) {
            require(cursor < bytes.size && shift <= 28) { "Malformed ULEB in DEX" }
            val b = bytes[cursor++].toInt() and 0xff
            value = value or ((b and 0x7f) shl shift)
            if (b and 0x80 == 0) return Uleb(value, offset, cursor)
            shift += 7
        }
    }

    /**
     * Walk the variable-sized code_item section from the map entry. The field at
     * +2 is ins_size (the incoming register words), not the bytecode length;
     * advancing by it desynchronizes at the first non-trivial method and makes
     * the next catch-handler bytes look like an invalid ULEB.
     */
    private fun repairCodeSection(bytes: ByteArray, start: Int, count: Int): Int {
        var cursor = start
        var repaired = 0
        repeat(count) {
            require(cursor >= 0 && cursor <= bytes.size - 16) {
                "code_item outside DEX"
            }
            val registers = readU16(bytes, cursor)
            val ins = readU16(bytes, cursor + 2)
            val tries = readU16(bytes, cursor + 6)
            val insnsSize = u32(bytes, cursor + 12)
            require(insnsSize >= 0) { "negative insns_size in DEX" }

            val codeEnd = cursor.toLong() + 16L + insnsSize.toLong() * 2L
            require(codeEnd >= cursor.toLong() && codeEnd <= bytes.size.toLong()) {
                "instructions outside DEX"
            }
            if (ins > registers) {
                putU16(bytes, cursor, ins)
                repaired++
            }

            var next = codeEnd.toInt()
            if (tries > 0) {
                if ((next and 3) != 0) next += 2
                require(next.toLong() + tries.toLong() * 8L <= bytes.size.toLong()) {
                    "try items outside DEX"
                }
                next += tries * 8
                val handlers = readUleb(bytes, next)
                require(handlers.value >= 0) { "negative catch-handler count in DEX" }
                next = handlers.next
                repeat(handlers.value) {
                    val handlerSize = readSleb(bytes, next)
                    next = handlerSize.next
                    val typedHandlers = if (handlerSize.value < 0) {
                        -handlerSize.value.toLong()
                    } else {
                        handlerSize.value.toLong()
                    }
                    require(typedHandlers <= Int.MAX_VALUE.toLong() &&
                            typedHandlers <= bytes.size.toLong()) {
                        "catch-handler count outside DEX"
                    }
                    repeat(typedHandlers.toInt()) {
                        next = readUleb(bytes, next).next
                        next = readUleb(bytes, next).next
                    }
                    if (handlerSize.value <= 0) {
                        next = readUleb(bytes, next).next
                    }
                }
            }
            val alignedNext = (next.toLong() + 3L) and -4L
            require(alignedNext <= bytes.size.toLong()) {
                "code_item alignment outside DEX"
            }
            cursor = alignedNext.toInt()
        }
        return repaired
    }

    private fun readSleb(bytes: ByteArray, offset: Int): Uleb {
        require(offset in bytes.indices) { "SLEB offset outside DEX" }
        var value = 0
        var shift = 0
        var cursor = offset
        var b: Int
        do {
            require(cursor < bytes.size && shift <= 28) { "Malformed SLEB in DEX" }
            b = bytes[cursor++].toInt() and 0xff
            value = value or ((b and 0x7f) shl shift)
            shift += 7
        } while (b and 0x80 != 0)
        if (shift < 32 && b and 0x40 != 0) value = value or (-1 shl shift)
        return Uleb(value, offset, cursor)
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
                ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
    }

    private fun u32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
                ((bytes[offset + 1].toInt() and 0xff) shl 8) or
                ((bytes[offset + 2].toInt() and 0xff) shl 16) or
                ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
        bytes[offset + 2] = (value ushr 16).toByte()
        bytes[offset + 3] = (value ushr 24).toByte()
    }

    private fun refreshDexIntegrity(bytes: ByteArray) {
        val signature = MessageDigest.getInstance("SHA-1")
            .digest(bytes.copyOfRange(32, bytes.size))
        signature.copyInto(bytes, 12)
        val adler = Adler32()
        adler.update(bytes, 12, bytes.size - 12)
        putU32(bytes, 8, adler.value.toInt())
    }
}
