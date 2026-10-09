package com.vmp.packer

import android.content.Context
import java.io.File
import java.io.FileOutputStream

/**
 * Bounded scan-result cache keyed by the APK SHA-256, raw-content CRC32, and
 * policy asset text. Entries are evicted oldest-first and are best-effort: a
 * cache read or write failure never fails a scan.
 */
internal object ScanCache {
    private const val FILE = "scan_cache.json"
    private const val MAX_ENTRIES = 200

    class CachedScan(
        val pkg: String?,
        val paths: List<String>,
        val counts: List<Int>,
        val total: Int,
        val savedAt: Long
    )

    fun load(ctx: Context): Map<String, CachedScan> {
        return try {
            val f = File(ctx.filesDir, FILE)
            if (!f.exists()) return emptyMap()
            val root = org.json.JSONObject(f.readText())
            val out = HashMap<String, CachedScan>()
            for (key in root.keys()) {
                val o = root.optJSONObject(key) ?: continue
                val pa = o.optJSONArray("paths") ?: continue
                val ca = o.optJSONArray("counts") ?: continue
                val paths = mutableListOf<String>()
                val counts = mutableListOf<Int>()
                for (i in 0 until pa.length()) paths.add(pa.getString(i))
                for (i in 0 until ca.length()) counts.add(ca.getInt(i))
                if (paths.size != counts.size) continue
                out[key] = CachedScan(
                    if (o.optString("pkg").isEmpty()) null else o.optString("pkg"),
                    paths, counts, o.optInt("total"), o.optLong("savedAt"))
            }
            out
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun put(ctx: Context, key: String, r: Packer.ScanResult) {
        try {
            val map = load(ctx).toMutableMap()
            map[key] = CachedScan(
                r.manifestPackage, r.pkgPaths, r.pkgCounts.toList(),
                r.totalMethods, System.currentTimeMillis())
            while (map.size > MAX_ENTRIES) {
                val oldest = map.entries.minByOrNull { it.value.savedAt }?.key ?: break
                map.remove(oldest)
            }
            val root = org.json.JSONObject()
            for ((k, e) in map) {
                val o = org.json.JSONObject()
                o.put("pkg", e.pkg ?: "")
                o.put("paths", org.json.JSONArray(e.paths))
                o.put("counts", org.json.JSONArray(e.counts))
                o.put("total", e.total)
                o.put("savedAt", e.savedAt)
                root.put(k, o)
            }
            val destination = File(ctx.filesDir, FILE)
            val temporary = File(ctx.filesDir, "$FILE.tmp")
            try {
                FileOutputStream(temporary).use { output ->
                    output.write(root.toString().toByteArray(Charsets.UTF_8))
                    output.fd.sync()
                }
                if (!temporary.renameTo(destination)) {
                    error("cannot atomically publish scan cache")
                }
            } finally {
                temporary.delete()
            }
        } catch (_: Exception) {
        }
    }
}
