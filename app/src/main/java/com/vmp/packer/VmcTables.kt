package com.vmp.packer

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Builds the metadata sections shared by one VMC container. */
internal class VmcTables(
    private val dex: DexParser,
    private val sparse: Boolean,
    private val offsetOf: (String?) -> Int
) {
    private fun buildSparseTable(ids: IntArray, recordFor: (Int) -> ByteArray): ByteArray {
        val records = ArrayList<ByteArray>(ids.size)
        for (id in ids) records.add(recordFor(id))
        val indexSize = 4 + ids.size * 8
        val buffer = ByteBuffer.allocate(indexSize + records.sumOf { it.size })
            .order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(ids.size)
        var position = indexSize
        for (i in ids.indices) {
            buffer.putInt(ids[i])
            buffer.putInt(position)
            position += records[i].size
        }
        for (record in records) buffer.put(record)
        return buffer.array()
    }

    private fun keptType(index: Int, keep: Set<String>): Boolean =
        dex.typeDesc(index) in keep

    fun buildTypeTable(keep: Set<String>?): ByteArray {
        if (sparse && keep != null) {
            val ids = (0 until dex.typeCount())
                .filter { keptType(it, keep) }
                .toIntArray()
            return buildSparseTable(ids) { index ->
                ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(offsetOf(dex.typeDesc(index)))
                    .array()
            }
        }

        val buffer = ByteBuffer.allocate(dex.typeCount() * 4)
            .order(ByteOrder.LITTLE_ENDIAN)
        for (index in 0 until dex.typeCount()) {
            buffer.putInt(offsetOf(dex.typeDesc(index)))
        }
        return buffer.array()
    }

    private fun protoRecord(index: Int): ByteArray {
        val params = dex.protoParams(index)
        val buffer = ByteBuffer.allocate(4 + params.size * 4 + 8)
            .order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(params.size)
        for (param in params) buffer.putInt(offsetOf(param))
        buffer.putInt(offsetOf(dex.protoShortyByIdx(index)))
        buffer.putInt(offsetOf(dex.jniSig(index)))
        return buffer.array()
    }

    private fun keptProtoIds(keep: Set<String>): Set<Int> {
        val result = HashSet<Int>()
        for (index in 0 until dex.methodCount()) {
            val method = dex.methodIdOffset(index)
            if (dex.stringByIdx(dex.u4(method + 4)) in keep &&
                dex.typeDesc(dex.u2(method)) in keep
            ) {
                result.add(dex.u2(method + 2))
            }
        }
        return result
    }

    fun buildProtoTable(keep: Set<String>?): ByteArray {
        if (sparse && keep != null) {
            val kept = keptProtoIds(keep)
            val ids = (0 until dex.protoCount())
                .filter { it in kept }
                .toIntArray()
            return buildSparseTable(ids) { index -> protoRecord(index) }
        }

        val output = ByteArrayOutputStream()
        for (index in 0 until dex.protoCount()) {
            output.write(protoRecord(index))
        }
        return output.toByteArray()
    }

    fun buildFieldTable(keep: Set<String>?): ByteArray {
        if (sparse && keep != null) {
            val ids = (0 until dex.fieldCount()).filter { index ->
                val field = dex.fieldIdOffset(index)
                dex.stringByIdx(dex.u4(field + 4)) in keep &&
                    dex.typeDesc(dex.u2(field)) in keep
            }.toIntArray()
            return buildSparseTable(ids) { index ->
                val field = dex.fieldIdOffset(index)
                ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
                    .putShort(dex.u2(field).toShort())
                    .putShort(dex.u2(field + 2).toShort())
                    .putInt(offsetOf(dex.stringByIdx(dex.u4(field + 4))))
                    .array()
            }
        }

        val buffer = ByteBuffer.allocate(dex.fieldCount() * 8)
            .order(ByteOrder.LITTLE_ENDIAN)
        for (index in 0 until dex.fieldCount()) {
            val field = dex.fieldIdOffset(index)
            buffer.putShort(dex.u2(field).toShort())
            buffer.putShort(dex.u2(field + 2).toShort())
            buffer.putInt(offsetOf(dex.stringByIdx(dex.u4(field + 4))))
        }
        return buffer.array()
    }

    fun buildMethodTable(keep: Set<String>?): ByteArray {
        if (sparse && keep != null) {
            val ids = (0 until dex.methodCount()).filter { index ->
                val method = dex.methodIdOffset(index)
                dex.stringByIdx(dex.u4(method + 4)) in keep &&
                    dex.typeDesc(dex.u2(method)) in keep
            }.toIntArray()
            return buildSparseTable(ids) { index ->
                val method = dex.methodIdOffset(index)
                ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
                    .putShort(dex.u2(method).toShort())
                    .putShort(dex.u2(method + 2).toShort())
                    .putInt(offsetOf(dex.stringByIdx(dex.u4(method + 4))))
                    .array()
            }
        }

        val buffer = ByteBuffer.allocate(dex.methodCount() * 8)
            .order(ByteOrder.LITTLE_ENDIAN)
        for (index in 0 until dex.methodCount()) {
            val method = dex.methodIdOffset(index)
            buffer.putShort(dex.u2(method).toShort())
            buffer.putShort(dex.u2(method + 2).toShort())
            buffer.putInt(offsetOf(dex.stringByIdx(dex.u4(method + 4))))
        }
        return buffer.array()
    }
}
