package com.vmp.packer

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.zip.ZipFile

internal const val MAX_APK_BYTES = 1024L * 1024L * 1024L
internal const val MAX_ZIP_ENTRY_BYTES = 256L * 1024L * 1024L

/** InputStream wrapper that enforces a limit while preserving streaming reads. */
class LimitedInputStream(input: InputStream, private val limit: Long) :
    java.io.FilterInputStream(input) {
    private var total = 0L

    init {
        require(limit >= 0) { "limit must be non-negative" }
    }

    private fun requested(length: Int): Int {
        if (length == 0) return 0
        val remaining = limit - total
        if (remaining < 0) throw IllegalArgumentException("Input exceeds $limit bytes")
        val probe = if (remaining == Long.MAX_VALUE) remaining else remaining + 1
        return minOf(length.toLong(), probe).toInt()
    }

    private fun record(count: Int): Int {
        if (count > 0) {
            total += count.toLong()
            if (total > limit) throw IllegalArgumentException("Input exceeds $limit bytes")
        }
        return count
    }

    override fun read(): Int {
        val value = super.read()
        if (value >= 0) {
            total++
            if (total > limit) throw IllegalArgumentException("Input exceeds $limit bytes")
        }
        return value
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        require(offset >= 0 && length >= 0 && offset <= buffer.size - length)
        if (length == 0) return 0
        return record(super.read(buffer, offset, requested(length)))
    }

    override fun skip(length: Long): Long {
        if (length <= 0) return 0
        val buffer = ByteArray(minOf(8192L, length).toInt())
        var skipped = 0L
        while (skipped < length) {
            val want = minOf(buffer.size.toLong(), length - skipped).toInt()
            val count = read(buffer, 0, want)
            if (count < 0) break
            skipped += count
        }
        return skipped
    }
}

/** Bounded readers for untrusted APK/ZIP input. */
object ApkUtil {
    fun copyLimited(input: InputStream, output: OutputStream, limit: Long) {
        require(limit >= 0) { "limit must be non-negative" }
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) {
                val one = input.read()
                if (one < 0) break
                total++
                if (total > limit) throw IllegalArgumentException("Input exceeds $limit bytes")
                output.write(one)
                continue
            }
            total += count
            if (total > limit) throw IllegalArgumentException("Input exceeds $limit bytes")
            output.write(buffer, 0, count)
        }
    }

    fun readLimited(input: InputStream, limit: Long): ByteArray {
        val output = ByteArrayOutputStream()
        copyLimited(input, output, limit)
        return output.toByteArray()
    }

    fun dexEntryNames(file: File): Set<String> {
        val names = LinkedHashSet<String>()
        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val name = entries.nextElement().name
                if (Regex("""classes\d*\.dex""").matches(name)) names.add(name)
            }
        }
        return names
    }

    fun readEntry(file: File, name: String): ByteArray? {
        val zip = ZipFile(file)
        try {
            val entry = zip.getEntry(name) ?: return null
            if (entry.size > MAX_ZIP_ENTRY_BYTES)
                throw IllegalArgumentException("ZIP entry $name exceeds $MAX_ZIP_ENTRY_BYTES bytes")
            return zip.getInputStream(entry).use { readLimited(it, MAX_ZIP_ENTRY_BYTES) }
        } finally {
            zip.close()
        }
    }
}
