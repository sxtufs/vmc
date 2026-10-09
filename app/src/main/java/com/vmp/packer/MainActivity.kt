package com.vmp.packer

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.appcompat.widget.SwitchCompat
import androidx.activity.result.contract.ActivityResultContracts
import android.view.ViewGroup
import android.widget.EditText
import android.text.Editable
import android.text.TextWatcher
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.Locale
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private var inputUri: Uri? = null
    private var mappingUri: Uri? = null
    private var mapping: ProguardMapping? = null
    private var mappingLoadJob: Job? = null

    private lateinit var inputCard: View
    private lateinit var inputName: TextView
    private lateinit var inputMeta: TextView
    private lateinit var mappingCard: View
    private lateinit var mappingName: TextView
    private lateinit var mappingMeta: TextView
    private lateinit var mappingClearBtn: TextView
    private lateinit var packBtn: View
    private lateinit var scanBtn: View
    private lateinit var debugSwitch: SwitchCompat
    private lateinit var identityEdit: android.widget.EditText
    private lateinit var identityRow: View
    private lateinit var jksStatus: TextView
    private lateinit var importJksBtn: TextView
    private lateinit var removeJksBtn: TextView
    private var customJksPassword: CharArray? = null
    private lateinit var logView: TextView
    private lateinit var logScroll: android.widget.ScrollView
    private lateinit var optionsView: View
    private var activeJob: Job? = null
    private var manifestResolveJob: Job? = null
    private val fileLogExecutor = Executors.newSingleThreadExecutor()
    private var uiLogTruncated = false
    @Volatile private var fileLogTruncated = false


    /**
     * In-memory breakdown memo keyed by "uri:totalMethods": a scan cache hit
     * carries no class data, and re-parsing every dex per dialog open is slow.
     * RAM only: persisting it would change every scan-cache key.
     */
    private var classMemo: Map<String, List<Pair<String, Int>>> = emptyMap()
    private var classMemoKey: String = ""

    private val pickLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            onApkPicked(uri)
        } else {
            log("No APK selected")
        }
    }

    private val jksPickLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            showJksImportDialog(uri)
        } else {
            log("No JKS selected")
        }
    }

    private val mappingPickLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            onMappingPicked(uri)
        } else {
            log("No mapping file selected")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.enableEdgeToEdge(window)
        setContentView(R.layout.activity_main)
        applySystemBarInsets()

        findViewById<android.widget.ImageButton>(R.id.gearBtn)
            .setOnClickListener { showSettingsDialog() }

        inputCard = findViewById(R.id.inputCard)
        inputName = findViewById(R.id.inputName)
        inputMeta = findViewById(R.id.inputMeta)
        mappingCard = findViewById(R.id.mappingCard)
        mappingName = findViewById(R.id.mappingName)
        mappingMeta = findViewById(R.id.mappingMeta)
        mappingClearBtn = findViewById(R.id.mappingClearBtn)
        mappingCard.setOnClickListener { openMappingPicker() }
        mappingClearBtn.setOnClickListener {
            clearMappingSelection()
            log("Mapping file cleared")
        }
        packBtn = findViewById(R.id.packBtn)
        scanBtn = findViewById(R.id.scanBtn)
        packBtn.isEnabled = false
        scanBtn.isEnabled = false
        logView = findViewById(R.id.log)
        logScroll = findViewById(R.id.logScroll)

        optionsView = layoutInflater.inflate(R.layout.dialog_options, null)
        debugSwitch = optionsView.findViewById(R.id.debugSwitch)
        debugSwitch.isChecked = getPrefs().getBoolean(PREF_DEBUG, false)
        identityEdit = optionsView.findViewById(R.id.identityEdit)
        identityEdit.setText(getPrefs().getString(PREF_IDENTITY, ""))
        identityRow = optionsView.findViewById(R.id.identityRow)
        jksStatus = optionsView.findViewById(R.id.jksStatus)
        importJksBtn = optionsView.findViewById(R.id.importJksBtn)
        removeJksBtn = optionsView.findViewById(R.id.removeJksBtn)
        applyIdentityEnabled()
        refreshJksUi()
        importJksBtn.setOnClickListener {
            jksPickLauncher.launch(arrayOf("application/octet-stream", "*/*"))
        }
        removeJksBtn.setOnClickListener {
            customJksPassword?.fill('\u0000')
            customJksPassword = null
            JksProfileStore.remove(this)
            refreshJksUi()
            log("Custom JKS removed; generated signing identity restored")
        }

        inputCard.setOnClickListener { openPicker() }
        findViewById<TextView>(R.id.copyLogBtn).setOnClickListener { copyLogToClipboard() }
        scanBtn.setOnClickListener { startScan() }

        packBtn.setOnClickListener {
            if (activeJob != null) {
                activeJob?.cancel()
                return@setOnClickListener
            }
            val uri = inputUri
            if (uri == null) {
                log("Pick an input APK first!")
                return@setOnClickListener
            }
            getPrefs().edit()
                .putBoolean(PREF_DEBUG, debugSwitch.isChecked)
                .putString(PREF_IDENTITY, identityEdit.text.toString().trim())
                .apply()
            startPack(uri)
        }
    }

    /** The identity row is always live: signing is no longer a toggle. */
    private fun applyIdentityEnabled() {
        identityRow.alpha = 1f
        identityEdit.isEnabled = true
    }

    private fun refreshJksUi() {
        val profile = JksProfileStore.load(this)
        if (profile != null && customJksPassword == null) {
            customJksPassword = JksProfileStore.loadPassword(this)
        }
        val customActive = profile != null
        identityEdit.isEnabled = !customActive
        identityEdit.isFocusable = !customActive
        identityEdit.isFocusableInTouchMode = !customActive
        identityEdit.isClickable = !customActive
        identityEdit.isLongClickable = !customActive
        identityEdit.isCursorVisible = !customActive
        identityEdit.hint = if (customActive)
            "Custom JKS selected"
        else "Blank uses the app package"
        identityRow.alpha = if (customActive) 0.5f else 1f

        if (profile == null) {
            jksStatus.text = "No custom JKS imported"
            removeJksBtn.visibility = View.GONE
            importJksBtn.text = "Import JKS"
            return
        }
        jksStatus.text = "${profile.name} · alias ${profile.alias}\n" +
                "SHA-256: ${profile.certSha256}"
        removeJksBtn.visibility = View.VISIBLE
        importJksBtn.text = "Import JKS"
    }

    private fun showJksImportDialog(uri: Uri) {
        val view = layoutInflater.inflate(R.layout.dialog_jks_import, null)
        val nameEdit = view.findViewById<EditText>(R.id.jksNameEdit)
        val aliasEdit = view.findViewById<EditText>(R.id.jksAliasEdit)
        val passwordEdit = view.findViewById<EditText>(R.id.jksPasswordEdit)
        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .create()
        val cancelButton = view.findViewById<TextView>(R.id.jksCancelBtn)
        val importButton = view.findViewById<TextView>(R.id.jksImportBtn)
        dialog.setOnShowListener {
            fun updateImportEnabled() {
                val enabled = nameEdit.text.toString().trim().isNotEmpty() &&
                        aliasEdit.text.toString().trim().isNotEmpty() &&
                        passwordEdit.text.toString().isNotEmpty()
                importButton.isEnabled = enabled
                importButton.alpha = if (enabled) 1f else 0.45f
            }
            val formWatcher = object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    updateImportEnabled()
                }
                override fun afterTextChanged(s: Editable?) = Unit
            }
            nameEdit.addTextChangedListener(formWatcher)
            aliasEdit.addTextChangedListener(formWatcher)
            passwordEdit.addTextChangedListener(formWatcher)
            cancelButton.setOnClickListener { dialog.dismiss() }
            importButton.setOnClickListener {
                val password = passwordEdit.text.toString().toCharArray()
                try {
                    val profile = JksProfileStore.importJks(
                        this, uri, nameEdit.text.toString(), aliasEdit.text.toString(), password
                    )
                    customJksPassword?.fill('\u0000')
                    customJksPassword = password.copyOf()
                    refreshJksUi()
                    log("Imported custom JKS '${profile.name}' with alias '${profile.alias}'")
                    dialog.dismiss()
                } catch (t: Throwable) {
                    passwordEdit.error = t.message ?: "Invalid JKS or password"
                } finally {
                    password.fill('\u0000')
                }
            }
            updateImportEnabled()
        }
        dialog.show()
        styleJksDialog(dialog)
    }

    private fun askForJksPassword(uri: Uri, profile: JksProfileStore.Profile) {
        val passwordEdit = EditText(this).apply {
            hint = "Password"
            background = getDrawable(R.drawable.bg_search_box)
            gravity = android.view.Gravity.CENTER_VERTICAL
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                    android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            minHeight = (48f * resources.displayMetrics.density).toInt()
            val horizontal = (16f * resources.displayMetrics.density).toInt()
            setPadding(horizontal, 0, horizontal, 0)
            textSize = 16f
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Keystore")
            .setView(passwordEdit)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Use", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val password = passwordEdit.text.toString().toCharArray()
                try {
                    JksProfileStore.validatePassword(profile, password)
                    JksProfileStore.rememberPassword(this, password)
                    customJksPassword?.fill('\u0000')
                    customJksPassword = password.copyOf()
                    dialog.dismiss()
                    startPack(uri)
                } catch (t: Throwable) {
                    passwordEdit.error = t.message ?: "Invalid JKS password"
                } finally {
                    password.fill('\u0000')
                }
            }
        }
        dialog.show()
        styleJksDialog(dialog)
    }

    private fun showSettingsDialog() {
        (optionsView.parent as? ViewGroup)?.removeView(optionsView)
        val d = AlertDialog.Builder(this).setView(optionsView).create()
        optionsView.findViewById<TextView>(R.id.btnClose).setOnClickListener { d.dismiss() }
        d.show()
        styleDialog(d)
    }

    private fun styleDialog(dialog: AlertDialog) {
        val window = dialog.window ?: return
        val margin = (24f * resources.displayMetrics.density).toInt()
        window.setBackgroundDrawableResource(R.drawable.bg_dialog)
        window.setLayout(
            resources.displayMetrics.widthPixels - margin * 2,
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
    }
    private fun styleJksDialog(dialog: AlertDialog) {
        styleDialog(dialog)
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.80f).toInt(),
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
    }


    /**
     * Keep the toolbar's background edge-to-edge while moving its controls below
     * the status bar. The rest of the screen only receives bottom/side insets so
     * the first card does not gain an unnecessary top gap.
     */
    private fun applySystemBarInsets() {
        val root = findViewById<View>(R.id.mainRoot)
        val toolbar = findViewById<View>(R.id.toolbar)
        val insetHost = window.decorView.findViewById<View>(android.R.id.content)
        val baseRootLeft = root.paddingLeft
        val baseRootTop = root.paddingTop
        val baseRootRight = root.paddingRight
        val baseRootBottom = root.paddingBottom
        val baseToolbarHeight = toolbar.layoutParams.height
        val baseToolbarLeft = toolbar.paddingLeft
        val baseToolbarTop = toolbar.paddingTop
        val baseToolbarRight = toolbar.paddingRight
        val baseToolbarBottom = toolbar.paddingBottom

        ViewCompat.setOnApplyWindowInsetsListener(insetHost) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                        WindowInsetsCompat.Type.displayCutout()
            )
            val toolbarParams = toolbar.layoutParams
            val toolbarHeight = baseToolbarHeight + bars.top
            if (toolbarParams.height != toolbarHeight) {
                toolbarParams.height = toolbarHeight
                toolbar.layoutParams = toolbarParams
            }
            toolbar.setPadding(
                baseToolbarLeft,
                baseToolbarTop + bars.top,
                baseToolbarRight,
                baseToolbarBottom
            )
            root.setPadding(
                baseRootLeft + bars.left,
                baseRootTop,
                baseRootRight + bars.right,
                baseRootBottom + bars.bottom
            )
            insets
        }
        ViewCompat.requestApplyInsets(insetHost)
        insetHost.post { ViewCompat.requestApplyInsets(insetHost) }
    }

    private fun getPrefs() = getSharedPreferences("vmp_packer", Context.MODE_PRIVATE)

    private fun openMappingPicker() {
        mappingPickLauncher.launch(
            arrayOf("text/plain", "text/*", "application/octet-stream")
        )
    }

    private fun mappingDisplayName(uri: Uri): String =
        uri.lastPathSegment
            ?.substringAfterLast('/')
            ?.substringAfterLast(':')
            ?.takeIf { it.isNotBlank() }
            ?: "mapping.txt"

    private fun clearMappingSelection() {
        mappingLoadJob?.cancel()
        mappingLoadJob = null
        mappingUri = null
        mapping = null
        mappingName.text = "R8 / ProGuard · Optional"
        mappingMeta.text = "Select mapping.txt to restore original class names"
        mappingClearBtn.visibility = View.GONE
        classMemo = emptyMap()
        classMemoKey = ""
    }

    private fun onMappingPicked(uri: Uri) {
        mappingLoadJob?.cancel()
        mappingUri = uri
        mapping = null
        mappingName.text = mappingDisplayName(uri)
        mappingMeta.text = "Loading mapping.txt…"
        mappingClearBtn.visibility = View.VISIBLE
        classMemo = emptyMap()
        classMemoKey = ""

        mappingLoadJob = lifecycleScope.launch {
            try {
                val parsed = withContext(Dispatchers.IO) {
                    val bytes = contentResolver.openInputStream(uri)?.use {
                        ApkUtil.readLimited(it, MAX_MAPPING_BYTES)
                    } ?: error("Cannot open mapping file")
                    ProguardMapping.parseUtf8(bytes)
                }
                if (uri != mappingUri) return@launch
                mapping = parsed
                val warningText = if (parsed.warnings.isEmpty()) "" else
                    " · ${parsed.warnings.size} warning(s)"
                mappingMeta.text = "${formattedCount(parsed.classCount)} classes mapped${warningText} · Tap to replace"
                log("Mapping loaded · ${formattedCount(parsed.classCount)} classes")
                if (debugSwitch.isChecked) {
                    log("Mapping fingerprint: ${parsed.fingerprint.take(12)}")
                }
                parsed.warnings.forEach { log("Mapping warning: $it") }
            } catch (_: CancellationException) {
            } catch (t: Throwable) {
                if (uri == mappingUri) {
                    mapping = null
                    mappingMeta.text = "Couldn’t load mapping.txt · Tap to replace"
                    log("ERROR: ${t.message}")
                }
            }
        }
    }

    private fun openPicker() {
        pickLauncher.launch(
            arrayOf(
                "application/vnd.android.package-archive",
                "application/octet-stream"
            )
        )
    }

    private fun onApkPicked(uri: Uri) {
        inputUri = uri
        // A mapping is build-specific; never carry it over to a different APK.
        clearMappingSelection()
        classMemo = emptyMap()
        classMemoKey = ""
        getPrefs().edit().remove("lastScanPkg").apply()
        logView.text = ""
        findViewById<View>(R.id.logEmpty).visibility = View.VISIBLE
        resetFileLog()

        var name: String? = null
        var size: Long = -1
        try {
            contentResolver.query(
                uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null
            )?.use { c ->
                if (c.moveToFirst()) {
                    val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val si = c.getColumnIndex(OpenableColumns.SIZE)
                    if (ni >= 0) name = c.getString(ni)
                    if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
                }
            }
        } catch (_: Exception) {
        }
        inputName.text = name ?: uri.lastPathSegment ?: "Selected APK"
        inputMeta.text = if (size >= 0)
            String.format(Locale.US, "%.1f MB · Tap to change", size / 1048576.0)
        else "Tap to change"
        scanBtn.isEnabled = true
        packBtn.isEnabled = true
        applyBtnAlpha()

        log("Selected APK: ${name ?: uri}")

        manifestResolveJob?.cancel()
        manifestResolveJob = lifecycleScope.launch {
            try {
                val pkg = withContext(Dispatchers.Default) {
                    var bytes: ByteArray? = null
                    contentResolver.openInputStream(uri)?.use { ins ->
                        java.util.zip.ZipInputStream(ins.buffered()).use { zis ->
                            var e = zis.nextEntry
                            while (e != null && bytes == null) {
                                if (e.name == "AndroidManifest.xml")
                                    bytes = ApkUtil.readLimited(zis, MAX_ZIP_ENTRY_BYTES)
                                e = zis.nextEntry
                            }
                        }
                    }
                    bytes?.let { AxmlPatcher.readTargets(it).manifestPackage }
                }
                if (uri != inputUri) return@launch
                getPrefs().edit().putString("lastScanPkg", pkg).apply()
                val n = savedExcludesFor(pkg).size
                if (n > 0) log("Saved exclusions for $pkg: $n package(s)")
            } catch (_: CancellationException) {
            } catch (t: Exception) {
                if (uri == inputUri)
                    log("(manifest package resolve failed: ${t.message})")
            }
        }
    }

    /** Exclusions are scoped to both the manifest package and exact mapping. */
    private fun excludedPrefs() =
        getSharedPreferences("vmp_excludes", Context.MODE_PRIVATE)

    private fun exclusionPrefsKey(pkg: String?, mappingForScope: ProguardMapping?): String =
        "${pkg ?: ""}|mapping:${mappingForScope?.fingerprint ?: "none"}"

    private fun storedExcludesForPackage(pkg: String?): Set<String> {
        val packageKey = pkg ?: ""
        val prefs = excludedPrefs()
        val exactNoneKey = exclusionPrefsKey(pkg, null)
        val candidateKeys = prefs.all.keys.filter {
            it == packageKey || it == exactNoneKey || it.startsWith("$packageKey|mapping:")
        }
        return candidateKeys.flatMap { key ->
            (prefs.all[key] as? Set<*>)?.filterIsInstance<String>().orEmpty()
        }.toSet()
    }

    private fun savedExcludesFor(
        pkg: String?,
        mappingForScope: ProguardMapping? = mapping,
        availablePaths: Set<String>? = null
    ): Set<String> {
        val exactKey = exclusionPrefsKey(pkg, mappingForScope)
        val prefs = excludedPrefs()
        val values = if (mappingForScope != null || availablePaths == null) {
            prefs.getStringSet(exactKey, emptySet()) ?: emptySet()
        } else {
            // With no mapping, old mapped/legacy exclusions may still be useful,
            // but only if their path is present in this scan's source labels.
            storedExcludesForPackage(pkg)
        }
        return if (availablePaths == null) values
        else values.filterTo(HashSet()) { availablePaths.contains(it.removePrefix("!")) }
    }

    /** Policy exclusions to apply before a scan; no-mapping entries are filtered after labels exist. */
    private fun scanExcludesFor(mappingForScope: ProguardMapping?): List<String> {
        val pkg = getPrefs().getString("lastScanPkg", null) ?: return emptyList()
        return if (mappingForScope != null) {
            savedExcludesFor(pkg, mappingForScope).toList()
        } else {
            storedExcludesForPackage(pkg).toList()
        }
    }

    private fun saveExcludesFor(
        pkg: String?,
        set: Set<String>,
        mappingForScope: ProguardMapping? = mapping
    ) {
        val key = exclusionPrefsKey(pkg, mappingForScope)
        excludedPrefs().edit().putStringSet(key, set).apply()
    }

    private fun availableExclusionPaths(res: Packer.ScanResult): Set<String> {
        val paths = HashSet<String>(res.pkgPaths)
        res.classCounts.values.forEach { classes ->
            classes.forEach { (path, _) -> paths.add(path) }
        }
        return paths
    }

    private fun excludeLineFor(pkgPath: String) = "!$pkgPath"

    /** Pill buttons are containers - alpha carries the disabled look. */
    private fun applyBtnAlpha() {
        scanBtn.alpha = if (scanBtn.isEnabled) 1f else 0.45f
        packBtn.alpha = if (packBtn.isEnabled) 1f else 0.45f
    }

    private fun startScan() {
        val uri = inputUri ?: return
        if (activeJob != null) return
        val runMapping = mapping
        if (mappingUri != null && runMapping == null) {
            log("Mapping is still loading or invalid; clear it or select a valid mapping.txt")
            return
        }
        scanBtn.isEnabled = false
        packBtn.isEnabled = false
        inputCard.isEnabled = false
        applyBtnAlpha()
        activeJob = lifecycleScope.launch {
            try {
                // The manifest resolver owns lastScanPkg; wait for it before
                // loading persisted exclusions for this APK.
                manifestResolveJob?.join()
                val runScanExcludes = scanExcludesFor(runMapping)
                val res = withContext(Dispatchers.Default) {
                    Packer.scanPackages(this@MainActivity, uri,
                        excludeLines = runScanExcludes,
                        mapping = runMapping,
                        onEvent = { event -> runOnUiThread { renderEvent(event) } }) {
                        runOnUiThread { log(it) }
                    }
                }
                if (uri != inputUri) return@launch
                val saved = savedExcludesFor(
                    res.manifestPackage,
                    runMapping,
                    availableExclusionPaths(res)
                )
                showExcludeDialog(res, saved, runMapping)
            } catch (_: CancellationException) {
                log("SCAN CANCELLED")
            } catch (t: Exception) {
                log("SCAN ERROR: ${t.message}")
                t.printStackTrace()
            } finally {
                activeJob = null
                scanBtn.isEnabled = true
                packBtn.isEnabled = true
                inputCard.isEnabled = true
                applyBtnAlpha()
            }
        }
    }

    private fun renderEvent(event: PackEvent) {
        if (event.phase == PackPhase.COMPLETE) return
        val progress = event.progress?.let { " ${it.times(100).toInt()}%" } ?: ""
        val phase = event.phase.name.replace('_', ' ')
            .lowercase()
            .replaceFirstChar { it.titlecase() }
        log("$phase$progress · ${event.message}")
    }

    private fun formattedCount(n: Int): String =
        java.text.DecimalFormat("#,###").format(n.toLong())

    private fun showExcludeDialog(
        res: Packer.ScanResult,
        saved: Set<String>,
        mappingForScan: ProguardMapping?
    ) {
        val view = layoutInflater.inflate(R.layout.dialog_preview, null)
        val checked = BooleanArray(res.pkgPaths.size) {
            !saved.contains(excludeLineFor(res.pkgPaths[it]))
        }
        val pkgSet = res.pkgPaths.toSet()
        val extraExcludes = HashSet(saved.filter {
            !pkgSet.contains(it.removePrefix("!"))
        })
        val memoKey = "${inputUri}:${res.totalMethods}:${mappingForScan?.fingerprint ?: "-"}"
        val cc: Map<String, List<Pair<String, Int>>> = when {
            res.classCounts.isNotEmpty() -> res.classCounts
            classMemoKey == memoKey -> classMemo
            else -> emptyMap()
        }
        if (res.classCounts.isNotEmpty()) {
            classMemo = cc
            classMemoKey = memoKey
        }
        val adapter = PackagePreviewAdapter(
            layoutInflater = layoutInflater,
            density = resources.displayMetrics.density,
            paths = res.pkgPaths,
            counts = res.pkgCounts,
            checked = checked,
            classCounts = cc,
            memoKey = memoKey,
            extraExcludes = extraExcludes,
            formatCount = ::formattedCount,
            onLog = ::log,
            onLoadClassCounts = { packagePath, onLoaded, onFailed ->
                val selectedUri = inputUri
                val selectedMapping = mappingForScan
                if (selectedUri == null) {
                    onFailed(IllegalStateException("No APK is selected"))
                } else if (mappingUri != null && selectedMapping == null) {
                    onFailed(IllegalStateException("The selected mapping is not ready"))
                } else {
                    lifecycleScope.launch {
                        try {
                            val fresh = Packer.scanPackages(
                                this@MainActivity,
                                selectedUri,
                                forceFresh = true,
                                packageFilter = packagePath,
                                excludeLines = scanExcludesFor(selectedMapping),
                                mapping = selectedMapping
                            ) { message -> runOnUiThread { log(message) } }
                            if (selectedUri == inputUri &&
                                mapping?.fingerprint == mappingForScan?.fingerprint) {
                                onLoaded(fresh.classCounts)
                            }
                        } catch (error: Exception) {
                            onFailed(error)
                        }
                    }
                }
            },
            onMemoUpdated = { updated ->
                classMemo = updated
                classMemoKey = memoKey
            }
        )

        val d = AlertDialog.Builder(this).setView(view).create()
        view.findViewById<TextView>(R.id.tvCount).text =
            getString(R.string.preview_methods, formattedCount(res.totalMethods))
        val lv = view.findViewById<MaxHeightListView>(R.id.lvPkgs)
        lv.maxHeightPx = (resources.displayMetrics.heightPixels * 0.55f).toInt()
        lv.adapter = adapter

        view.findViewById<EditText>(R.id.etSearch).addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { adapter.filter(s?.toString() ?: "") }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        view.findViewById<View>(R.id.btnSelectAll).setOnClickListener {
            adapter.setAll(true)
        }
        view.findViewById<View>(R.id.btnClearAll).setOnClickListener {
            adapter.setAll(false)
        }
        view.findViewById<TextView>(R.id.tvCancel).setOnClickListener { d.dismiss() }
        view.findViewById<TextView>(R.id.tvSave).setOnClickListener {
            val excludes = HashSet<String>()
            for (i in res.pkgPaths.indices)
                if (!checked[i]) excludes += excludeLineFor(res.pkgPaths[i])
            excludes += adapter.extraExcludes
            saveExcludesFor(res.manifestPackage, excludes, mappingForScan)
            val keep = checked.count { it }
            val clsN = excludes.count { !pkgSet.contains(it.removePrefix("!")) }
            log("Exclusions saved: ${excludes.size - clsN} package(s) + $clsN " +
                    "class/method(s) excluded, $keep package(s) kept")
            d.dismiss()
        }
        d.show()
        styleDialog(d)
    }

    private fun setPackRunning(running: Boolean) {
        packBtn.findViewById<TextView>(R.id.packLabel).text =
            if (running) "CANCEL" else "PACK"
        packBtn.contentDescription = if (running) "Cancel packing" else "Pack APK"
    }

    private fun startPack(uri: Uri) {
        if (activeJob != null) return
        val profile = JksProfileStore.load(this)
        if (profile != null && customJksPassword == null) {
            askForJksPassword(uri, profile)
            return
        }
        startPackNow(uri, profile)
    }

    private fun startPackNow(uri: Uri, profile: JksProfileStore.Profile?) {
        if (activeJob != null) return
        val runMapping = mapping
        if (mappingUri != null && runMapping == null) {
            log("Mapping is still loading or invalid; clear it or select a valid mapping.txt")
            return
        }

        val runDebugMode = debugSwitch.isChecked
        val runIdentityTag = getPrefs().getString(PREF_IDENTITY, "")
            ?.takeIf { it.isNotBlank() }
        val runJksPassword = customJksPassword?.copyOf()

        packBtn.isEnabled = true
        inputCard.isEnabled = false
        scanBtn.isEnabled = false
        setPackRunning(true)
        applyBtnAlpha()

        activeJob = lifecycleScope.launch {
            try {
                manifestResolveJob?.join()
                val runPackage = getPrefs().getString("lastScanPkg", null)
                val runExcludes = savedExcludesFor(runPackage, runMapping)
                val output: File = withContext(Dispatchers.Default) {
                    val signingSource = if (profile != null) {
                        SigningSource.ImportedJks(
                            profile.file,
                            profile.alias,
                            runJksPassword
                                ?: error("Custom JKS password is not available")
                        )
                    } else null
                    try {
                        Packer.pack(this@MainActivity, uri,
                            debugMode = runDebugMode,
                            identityTag = runIdentityTag,
                            signingSource = signingSource,
                            mapping = runMapping,
                            excludeLines = runExcludes.toList(),
                            onEvent = { event -> runOnUiThread { renderEvent(event) } }) {
                            runOnUiThread { log(it) }
                        }
                    } finally {
                        (signingSource as? SigningSource.ImportedJks)?.clearPassword()
                    }
                }
                log("Done! Output: ${output.absolutePath}")
            } catch (_: CancellationException) {
                Packer.cleanupCancelledPack(this@MainActivity)
                log("PACK CANCELLED")
            } catch (t: Exception) {
                log("ERROR: ${t.message}")
                t.printStackTrace()
            } finally {
                runJksPassword?.fill('\u0000')
                activeJob = null
                setPackRunning(false)
                packBtn.isEnabled = true
                inputCard.isEnabled = true
                scanBtn.isEnabled = inputUri != null
                applyBtnAlpha()
            }
        }
    }

    private fun copyLogToClipboard() {
        val text = logView.text?.toString() ?: return
        if (text.isBlank()) return
        try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("vmp_log", text))
            android.widget.Toast.makeText(this, "Log copied", android.widget.Toast.LENGTH_SHORT).show()
        } catch (_: Throwable) {
            android.widget.Toast.makeText(this, "Log is too large to copy", android.widget.Toast.LENGTH_SHORT).show()
        }
    }

    private fun resetFileLog() {
        uiLogTruncated = false
        fileLogTruncated = false
        try {
            fileLogExecutor.execute {
                try {
                    val dir = getExternalFilesDir(null) ?: cacheDir
                    File(dir, "vmc.log").writeText("")
                } catch (_: Exception) {
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun log(message: String) {
        findViewById<View>(R.id.logEmpty).visibility = View.GONE
        val line = message + "\n"
        if (!uiLogTruncated) {
            val currentLength = logView.text?.length ?: 0
            if (currentLength + line.length <= MAX_UI_LOG_CHARS) {
                logView.append(line)
            } else {
                logView.append("\n[Log view truncated; full bounded log is in vmc.log]\n")
                uiLogTruncated = true
            }
        }

        try {
            fileLogExecutor.execute { appendFileLog(line) }
        } catch (_: Exception) {
        }
        logScroll.post { logScroll.fullScroll(View.FOCUS_DOWN) }
    }

    private fun appendFileLog(line: String) {
        if (fileLogTruncated) return
        try {
            val dir = getExternalFilesDir(null) ?: cacheDir
            val logFile = File(dir, "vmc.log")
            val bytes = line.toByteArray(Charsets.UTF_8)
            if (logFile.length() + bytes.size <= MAX_FILE_LOG_BYTES) {
                FileOutputStream(logFile, true).use { it.write(bytes) }
            } else {
                val marker = "[Log file truncated at ${MAX_FILE_LOG_BYTES} bytes]\n"
                    .toByteArray(Charsets.UTF_8)
                if (logFile.length() + marker.size <= MAX_FILE_LOG_BYTES) {
                    FileOutputStream(logFile, true).use { it.write(marker) }
                }
                fileLogTruncated = true
            }
        } catch (_: Exception) {
        }
    }

    override fun onDestroy() {
        manifestResolveJob?.cancel()
        mappingLoadJob?.cancel()
        customJksPassword?.fill('\u0000')
        customJksPassword = null
        fileLogExecutor.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val PREF_DEBUG = "debugMode"
        private const val PREF_IDENTITY = "identityTag"
        private const val MAX_UI_LOG_CHARS = 256 * 1024
        private const val MAX_FILE_LOG_BYTES = 2L * 1024L * 1024L
        private const val MAX_MAPPING_BYTES = 64L * 1024L * 1024L
    }
}

