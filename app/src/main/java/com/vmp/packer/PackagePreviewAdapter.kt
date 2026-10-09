package com.vmp.packer

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.CheckBox
import android.widget.TextView

/** One rendered row in the package/class preview list. */
private class PkgRow(
    val pkgIdx: Int,
    val classPath: String?,
    val label: String,
    val count: Int,
    val excl: Int = 0
)

/**
 * Package/class exclusion adapter. UI orchestration and background scanning stay
 * in MainActivity; this class owns only list state, filtering, and row behavior.
 */
internal class PackagePreviewAdapter(
    private val layoutInflater: LayoutInflater,
    private val density: Float,
    private val paths: List<String>,
    private val counts: IntArray,
    val checked: BooleanArray,
    private var classCounts: Map<String, List<Pair<String, Int>>>,
    private val memoKey: String,
    val extraExcludes: MutableSet<String>,
    private val formatCount: (Int) -> String,
    private val onLog: (String) -> Unit,
    private val onLoadClassCounts: (
        packagePath: String,
        onLoaded: (Map<String, List<Pair<String, Int>>>) -> Unit,
        onFailed: (Throwable) -> Unit
    ) -> Unit,
    private val onMemoUpdated: (Map<String, List<Pair<String, Int>>>) -> Unit
) : BaseAdapter() {
    var query: String = ""
        private set

    private val expanded = HashSet<Int>()
    private val fetching = HashSet<Int>()
    private var cache: List<PkgRow>? = null

    private fun matches(s: String) =
        query.isEmpty() || s.contains(query, ignoreCase = true)

    private fun inheritedExclusionParent(path: String): String? =
        extraExcludes.asSequence()
            .map { it.removePrefix("!") }
            .filter { it.isNotEmpty() && !it.contains("->") }
            .firstOrNull { parent ->
                path.startsWith("$parent$") || path.startsWith("$parent/")
            }

    private fun isExcludedClass(path: String): Boolean =
        extraExcludes.contains("!$path") || inheritedExclusionParent(path) != null

    private fun excludedPerPackage(): Map<String, Int> {
        if (extraExcludes.isEmpty()) return emptyMap()
        val result = HashMap<String, Int>()
        for ((pkg, classes) in classCounts) {
            val excluded = classes.count { (path, _) -> isExcludedClass(path) }
            if (excluded > 0) result[pkg] = excluded
        }
        // If class details have not been loaded yet, retain direct exclusions
        // as a fallback package indicator.
        for (line in extraExcludes) {
            val path = line.removePrefix("!")
            if (path.contains("->")) continue
            val pkg = path.substringBeforeLast('/')
            if (!classCounts.containsKey(pkg))
                result[pkg] = (result[pkg] ?: 0) + 1
        }
        return result
    }

    private fun classLabel(path: String): String {
        val simple = path.substringAfterLast('/')
        if (simple.isEmpty()) return simple
        if (simple.any { it in 'A'..'Z' || it in 'a'..'z' }) return simple
        val cp = simple.codePointAt(0)
        if (cp <= 0x7F) return simple
        return simple + " (U+" + String.format("%04X", cp) + ")"
    }

    private fun build(): List<PkgRow> {
        val result = ArrayList<PkgRow>()
        val excludedByPackage = excludedPerPackage()
        for (i in paths.indices) {
            val all = classCounts[paths[i]] ?: emptyList()
            val hits = if (query.isEmpty()) all else all.filter {
                matches(it.first) || matches(classLabel(it.first))
            }
            val packageHit = matches(paths[i])
            if (!packageHit && hits.isEmpty()) continue

            result.add(PkgRow(i, null, paths[i], counts[i],
                    excludedByPackage[paths[i]] ?: 0))
            val open = expanded.contains(i) ||
                    (query.isNotEmpty() && hits.isNotEmpty() && !packageHit)
            if (open && all.isNotEmpty()) {
                for ((path, count) in (if (query.isEmpty()) all else hits)) {
                    result.add(PkgRow(i, path, classLabel(path), count))
                }
            }
        }
        return result
    }

    private fun rows(): List<PkgRow> = cache ?: build().also { cache = it }

    override fun notifyDataSetChanged() {
        cache = null
        super.notifyDataSetChanged()
    }

    override fun getCount() = rows().size
    override fun getItem(position: Int) = rows()[position].label
    override fun getItemId(position: Int) = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: layoutInflater.inflate(R.layout.item_package, parent, false)
        val row = rows()[position]
        val classPath = row.classPath
        val inheritedParent = classPath?.let { inheritedExclusionParent(it) }
        val inherited = inheritedParent != null
        val classExcluded = classPath != null && isExcludedClass(classPath)

        val checkBox = view.findViewById<CheckBox>(R.id.pkgCheck)
        checkBox.isChecked = if (classPath != null) !classExcluded else checked[row.pkgIdx]
        checkBox.isEnabled = classPath == null || !inherited
        checkBox.contentDescription = when {
            inherited -> "Excluded through $inheritedParent"
            classPath != null && classExcluded -> "Excluded class"
            classPath != null -> "Included class"
            else -> "Package selection"
        }
        view.findViewById<TextView>(R.id.pkgCount).text =
            if (classPath == null && row.excl > 0)
                "${formatCount(row.count)} · ${row.excl} excl"
            else formatCount(row.count)
        view.findViewById<TextView>(R.id.pkgName).text =
            if (inherited) "${row.label} · inherited" else row.label
        view.setPaddingRelative(
            if (classPath != null) dp(34) else dp(16),
            view.paddingTop,
            view.paddingEnd,
            view.paddingBottom
        )

        val expand = view.findViewById<View>(R.id.pkgExpand)
        expand.visibility = if (classPath != null) View.INVISIBLE else View.VISIBLE
        expand.rotation = if (expanded.contains(row.pkgIdx)) 90f else 0f
        expand.setOnClickListener {
            val index = row.pkgIdx
            if (!expanded.remove(index)) expanded.add(index)
            notifyDataSetChanged()
            if (expanded.contains(index) &&
                !classCounts.containsKey(paths[index]) &&
                !fetching.contains(index)
            ) {
                fetching.add(index)
                val packagePath = paths[index]
                onLog("loading class breakdown for $packagePath...")
                onLoadClassCounts(
                    packagePath,
                    { fresh ->
                        fetching.remove(index)
                        mergeClassCounts(fresh)
                    },
                    { error ->
                        fetching.remove(index)
                        onLog("class breakdown failed: ${error.message}")
                    }
                )
            }
        }

        view.setOnClickListener {
            if (classPath != null) {
                if (inherited) {
                    onLog("${row.label} is excluded through $inheritedParent")
                } else {
                    val exclusion = "!$classPath"
                    if (!extraExcludes.remove(exclusion)) extraExcludes.add(exclusion)
                }
            } else {
                checked[row.pkgIdx] = !checked[row.pkgIdx]
            }
            notifyDataSetChanged()
        }

        view.setOnLongClickListener {
            if (classPath == null) return@setOnLongClickListener false
            if (inherited) {
                onLog("${row.label} is excluded through $inheritedParent")
                return@setOnLongClickListener true
            }
            val packagePath = paths[row.pkgIdx]
            val siblings = classCounts[packagePath] ?: emptyList()
            var excluded = 0
            for ((sibling, _) in siblings) {
                if (sibling == classPath) extraExcludes.remove("!$sibling")
                else if (extraExcludes.add("!$sibling")) excluded++
            }
            val wasOff = !checked[row.pkgIdx]
            checked[row.pkgIdx] = true
            val simple = classPath.substringAfterLast('/')
            val already = (siblings.size - 1 - excluded).coerceAtLeast(0)
            val message = if (excluded == 0 && already > 0)
                "Isolated $simple: already isolated ($already sibling(s) excluded)"
            else "Isolated $simple: $excluded sibling(s) excluded"
            onLog(message + if (wasOff) " and package $packagePath re-included" else "")
            notifyDataSetChanged()
            true
        }
        return view
    }

    private fun mergeClassCounts(newCounts: Map<String, List<Pair<String, Int>>>) {
        if (newCounts.isEmpty()) return
        classCounts = classCounts + newCounts
        onMemoUpdated(classCounts)
        notifyDataSetChanged()
    }

    fun filter(value: String) {
        query = value
        notifyDataSetChanged()
    }

    fun setAll(value: Boolean) {
        for (i in checked.indices) checked[i] = value
        extraExcludes.clear()
        notifyDataSetChanged()
    }

    private fun dp(value: Int) = (value * density).toInt()
}
