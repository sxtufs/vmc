package com.vmp.packer

import android.content.Context
import android.net.Uri
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

/**
 * Packs one input APK: read its manifest and dexes, build a VMC container per
 * dex, rewrite the dexes into native stubs, rebuild the APK with libVMP, sign it.
 */
object Packer {

    suspend fun pack(
        ctx: Context,
        inputUri: Uri,
        /** Safe APK basename; null/blank = derive a safe name from the target package. */
        outName: String? = null,
        debugMode: Boolean = false,
        /** null/blank = ephemeral unique cert per output; non-blank = stable
         *  named identity, so re-packed builds keep installing over each other. */
        identityTag: String? = null,
        /** Optional imported JKS signer. When present it takes precedence over identityTag. */
        signingSource: SigningSource? = null,
        /** Optional ProGuard/R8 mapping for the exact input APK build. */
        mapping: ProguardMapping? = null,
        excludeLines: List<String> = emptyList(),
        onEvent: ((PackEvent) -> Unit)? = null,
        onLog: (String) -> Unit
    ): File = withContext(Dispatchers.IO) {
        emit(onEvent, PackEvent(PackPhase.PREFLIGHT, message = "Starting pack"))

        if (debugMode) {
            val selfTestOk = SelfTest.run(ctx) { log(onLog, it) }
            if (!selfTestOk)
                error("Debug self-test failed; refusing to produce an APK")
        }

        val cacheDir = File(ctx.cacheDir, "vmpack").apply { mkdirs() }
        val input = File(cacheDir, "input.apk")
        ctx.contentResolver.openInputStream(inputUri)?.use { inputStream ->
            FileOutputStream(input).use {
                ApkUtil.copyLimited(inputStream, it, MAX_APK_BYTES)
            }
        } ?: error("Cannot open input APK")
        log(onLog, "Input APK: ${input.absolutePath} (${input.length()} bytes)")
        if (mapping != null) {
            log(onLog, "Mapping: ${mapping.classCount} classes, fingerprint=${mapping.fingerprint.take(12)}")
            mapping.warnings.forEach { log(onLog, "  WARNING: $it") }
        }

        val abis = AbiPreflight.declaredAbis(input)
        log(onLog, "Input APK ABIs: ${abis.joinToString()}")

        val vmpAssets = ctx.assets.list("vmp")?.toList() ?: emptyList()
        val uncovered = AbiPreflight.uncovered(abis, vmpAssets)
        if (uncovered.isNotEmpty())
            error(AbiPreflight.refusal(uncovered))

        val soBytesByAbi = LinkedHashMap<String, ByteArray?>()
        for (abi in abis) {
            currentCoroutineContext().ensureActive()
            val asset = AbiPreflight.vmcAssetFor(abi)
            soBytesByAbi[abi] = if (asset == null) null else try {
                ctx.assets.open(asset).use { it.readBytes() }
            } catch (_: Exception) {
                null
            }
        }

        val probe = RuntimeCapabilityProbe.probe(soBytesByAbi)
        val cap = probe.cap
        RuntimeCapabilityProbe.requireFloor(probe)
        log(onLog, RuntimeCapabilityProbe.verdict(probe, abis))

        val manifestBytes = ApkUtil.readEntry(input, "AndroidManifest.xml")
            ?: error("Input APK has no AndroidManifest.xml")
        log(onLog, "Read AndroidManifest.xml (${manifestBytes.size} bytes)")

        val targets = try {
            AxmlPatcher.readTargets(manifestBytes)
        } catch (t: Throwable) {
            log(onLog, "  readTargets FAILED: ${t.javaClass.simpleName}: ${t.message}")
            if (debugMode) {
                t.stackTrace.take(10).forEach { log(onLog, "    at $it") }
            }
            throw t
        }

        val whitelist = deriveWhitelist(targets, excludeLines, mapping, onLog)
        val activeExcludes = whitelist.activeExcludes
        if (activeExcludes.isNotEmpty()) {
            log(onLog, "  EXCLUDED from virtualization: $activeExcludes")
        }
        if (whitelist.targetPrefixes.isEmpty()) {
            log(onLog, "  WARNING: no whitelist derived from manifest (package=" +
                    "${targets.manifestPackage}, application=${targets.applicationClass}); " +
                    "falling back to legacy blacklist policy")
        } else {
            log(onLog, "  Whitelist: ${summarize(whitelist.targetPrefixes)}")
        }

        val appClassFqcn = targets.applicationClass?.let { n ->
            when {
                n.startsWith(".") -> targets.manifestPackage?.let { pkg -> pkg + n } ?: n
                !n.contains('.') -> targets.manifestPackage?.let { pkg -> "$pkg.$n" } ?: n
                else -> n
            }
        }
        val appSourceClassDesc = appClassFqcn?.let { n ->
            if (n.startsWith("L") && n.endsWith(";")) n
            else "L${n.replace('.', '/')};"
        }

        val componentDesc: (String) -> String? = { cn ->
            resolveComponentName(cn, targets.manifestPackage)
                ?.let { "L${it.replace('.', '/')};" }
        }

        val allComponentSourceDescs = targets.componentClasses
            .mapNotNull { componentDesc(it) }
            .filter { !VirtualizationPolicy.isLibraryClass(it) }
            .distinct()

        val componentSourceDescs = if (appSourceClassDesc == null) {
            targets.contextComponentClasses
                .mapNotNull { componentDesc(it) }
                .filter { !VirtualizationPolicy.isLibraryClass(it) }
                .distinct()
        } else emptyList()

        val dexNames = ArrayList<String>()
        val dexBytes = ArrayList<ByteArray>()
        var index = 0
        while (true) {
            currentCoroutineContext().ensureActive()
            val name = if (index == 0) "classes.dex" else "classes${index + 1}.dex"
            val bytes = ApkUtil.readEntry(input, name)
            if (bytes == null) break
            dexNames.add(name)
            dexBytes.add(bytes)
            index++
        }
        if (dexBytes.isEmpty()) error("Input APK has no dex files")
        val extraDexes = ApkUtil.dexEntryNames(input) - dexNames.toSet()
        if (extraDexes.isNotEmpty()) {
            error("Input APK has non-contiguous dex entries: ${extraDexes.joinToString()}")
        }
        log(onLog, "Found ${dexBytes.size} dex file(s): ${dexNames.joinToString()}")

        val definedClasses = if (mapping == null) {
            emptySet<String>()
        } else collectDefinedClasses(dexBytes)
        val appClassDesc = resolveMappedDescriptor(
                appSourceClassDesc, mapping, definedClasses)
        val allComponentDescs = allComponentSourceDescs.mapNotNull {
            resolveMappedDescriptor(it, mapping, definedClasses)
        }.distinct()
        var componentDescs = if (appClassDesc == null) {
            componentSourceDescs.mapNotNull {
                resolveMappedDescriptor(it, mapping, definedClasses)
            }.distinct()
        } else emptyList()
        if (appClassDesc != appSourceClassDesc && appClassDesc != null) {
            log(onLog, "  Mapping resolved Application ${appSourceClassDesc ?: "?"} -> $appClassDesc")
        }
        if (componentDescs.isNotEmpty()) {
            log(onLog, "  initVM component injection candidates (${componentDescs.size}): " +
                    componentDescs.joinToString(", "))
        }
        if (appClassDesc == null && allComponentDescs.size > componentDescs.size) {
            log(onLog, "  initVM injection SKIPPED for " +
                    (allComponentDescs.size - componentDescs.size) +
                    " non-Context component(s) (receiver/provider) - they have " +
                    "no attachBaseContext hook; their constructors are still " +
                    "exempt from virtualization via the pre-initVM scan")
        }

        var invalidComponentClasses: List<String> = emptyList()
        var effectiveWhitelist = whitelist
        if (componentDescs.isNotEmpty()) {
            val superclasses = collectClassSuperclasses(dexBytes)
            val finalAttachBases = collectFinalAttachBases(dexBytes)
            val invalid = componentDescs.filterNot {
                hasResolvableContextBase(it, superclasses, finalAttachBases)
            }
            invalidComponentClasses = invalid
            if (invalid.isNotEmpty()) {
                val invalidSet = invalid.toSet()
                componentDescs = componentDescs.filterNot { it in invalidSet }
                effectiveWhitelist = whitelist.copy(
                    excludeClassPrefixes = whitelist.excludeClassPrefixes + invalid
                )
                log(onLog, "  WARNING: skipped ${invalid.size} component hook target(s) with " +
                        "unresolved or final superclass: ${summarize(invalid)}")
            }
            if (componentDescs.isNotEmpty()) {
                log(onLog, "  initVM usable component injection targets " +
                        "(${componentDescs.size}): ${summarize(componentDescs)}")
            }
        }
        if (appClassDesc == null && componentDescs.isEmpty()) {
            error("No custom Application or usable activity/service " +
                    "attachBaseContext hook exists for initVM")
        }

        val earlyClasses = HashSet<String>()
        appClassDesc?.let { earlyClasses.add(it) }
        earlyClasses.addAll(allComponentDescs)
        emit(onEvent, PackEvent(PackPhase.PRE_VM, message = "Analyzing pre-initVM reachability"))
        val clinitKeys = ClinitScan.clinitExemptKeys(
            dexBytes, earlyClasses, effectiveWhitelist,
            { log(onLog, it) }
        )

        val cfg = PackConfig(runtimeMaxContainerVersion = cap)
        val policy = effectiveWhitelist.withClinitExempt(clinitKeys)
        val skips = SkipLog()

        val id = PackIdentity.draw()
        val libName = id.libName
        val attachOrigName = id.attachOrigName
        val containerAsset = id.containerAsset
        val loaderClassSlash = id.loaderClassSlash
        val loaderClassDesc = id.loaderClassDesc
        log(onLog, "Per-pack identity: lib$libName.so / assets/$containerAsset / $loaderClassDesc")

        val loaderCandidates = if (appClassDesc != null) {
            setOf(appClassDesc)
        } else {
            componentDescs.toSet()
        }
        val locatedLoaderDex = locateLoaderDex(dexBytes, loaderCandidates, loaderClassDesc)
        val applicationIsFinal = appClassDesc != null && locatedLoaderDex >= 0 &&
                isFinalClass(dexBytes[locatedLoaderDex], appClassDesc)
        var standaloneApplicationLoader = appClassDesc != null &&
                locatedLoaderDex >= 0 && !applicationIsFinal
        if (standaloneApplicationLoader) {
            val replacement = loaderClassSlash.replace('/', '.')
            val canPatchManifest = runCatching {
                AxmlPatcher.patch(manifestBytes.copyOf(), replacement)
            }.isSuccess
            if (!canPatchManifest) {
                standaloneApplicationLoader = false
                log(onLog, "Application name cannot be replaced in-place; " +
                        "falling back to an in-place Application hook")
            }
        }
        val loaderDexIndex = if (locatedLoaderDex >= 0) locatedLoaderDex else 0
        when {
            standaloneApplicationLoader ->
                log(onLog, "Application dex is protected from reserialization; using a standalone loader dex")
            applicationIsFinal ->
                log(onLog, "Application class is final; using an in-place loader hook")
            else -> log(onLog, "Loader injection dex: ${dexNames[loaderDexIndex]}")
        }

        val newDexes = ArrayList<ByteArray>()
        val vmcs = ArrayList<ByteArray>()
        var totalVirtualized = 0
        var totalCandidates = 0
        var totalVmcBytes = 0
        val dexPlans = ArrayList<DexPlan>()
        for (i in dexBytes.indices) {
            currentCoroutineContext().ensureActive()
            emit(onEvent, PackEvent(PackPhase.DEX,
                    message = "Processing ${dexNames[i]}", current = i + 1, total = dexBytes.size))
            val isLoaderDex = !standaloneApplicationLoader && i == loaderDexIndex
            val parser = try {
                DexParser(dexBytes[i], policy, skips)
            } catch (t: Throwable) {
                error("${dexNames[i]} cannot be safely parsed: ${t.message}")
            }
            log(onLog, "  strings=${parser.stringCount()} types=${parser.typeCount()} " +
                    "protos=${parser.protoCount()} methods=${parser.methodCount()} " +
                    "classes=${parser.classDefCount()}")

            val vkeys = parser.virtualizableKeys()
            totalCandidates += vkeys.size
            totalVirtualized += vkeys.size

            val needsRewrite = isLoaderDex || vkeys.isNotEmpty() ||
                    (!standaloneApplicationLoader && appClassDesc != null && parser.hasClass(appClassDesc)) ||
                    componentDescs.any { parser.hasClass(it) }

            if (needsRewrite) {
                val writer = VmcWriter(parser, cfg)
                writer.onPermSkip = { log(onLog, "  $it") }
                if (vkeys.isNotEmpty() && cap >= 4) {
                    writer.insnStarts = try {
                        InsnPerm.collectStarts(dexBytes[i], vkeys) { parser.insnsSizeOf(it) }
                    } catch (t: Exception) {
                        log(onLog, "  perm: ${t.javaClass.simpleName}: ${t.message}")
                        null
                    }
                    if (cap >= IrCodec.IR_FUSE_CAP)
                        writer.insnTargets = try {
                            InsnPerm.collectTargets(dexBytes[i], vkeys) { parser.insnsSizeOf(it) }
                        } catch (t: Exception) { null }
                }
                val vmc = writer.build()
                vmcs.add(vmc)
                totalVmcBytes += vmc.size
                log(onLog, "  VMC built: ${vmc.size} bytes, " +
                        "${vkeys.size} methods virtualized")
                log(onLog, "    VMC layout: ${writer.lastBreakdown}")
                if (writer.missedStrings.isNotEmpty()) {
                    log(onLog, "    !! ${writer.missedStrings.size} string(s) fell back to " +
                            "offset 0 (corrupt names/signatures): " +
                            writer.missedStrings.take(12).joinToString(", "))
                }

                val rewritten = DexRewriter.rewrite(
                    dexBytes[i], parser, injectLoader = isLoaderDex,
                    loaderClass = loaderClassDesc,
                    appClassName = if (!standaloneApplicationLoader && isLoaderDex)
                        appClassDesc else null,
                    componentClassDescs = componentDescs,
                    libName = libName,
                    attachOrigName = attachOrigName,
                    debugMode = debugMode
                ) { log(onLog, "  $it") }
                DexRewriter.verifyIncomingFrames(rewritten, dexNames[i])
                newDexes.add(rewritten)
                dexPlans.add(DexPlan(
                    name = dexNames[i], inputBytes = dexBytes[i].size,
                    candidateMethods = vkeys.size, virtualizedMethods = vkeys.size,
                    vmcBytes = vmc.size, rewritten = true
                ))
            } else {
                val vmc = emptyVmcContainer()
                vmcs.add(vmc)
                totalVmcBytes += vmc.size
                newDexes.add(dexBytes[i])
                dexPlans.add(DexPlan(
                    name = dexNames[i], inputBytes = dexBytes[i].size,
                    candidateMethods = vkeys.size, virtualizedMethods = 0,
                    vmcBytes = vmc.size, rewritten = false,
                    skipReason = "no virtualizable methods or injection target"
                ))
                log(onLog, "  SKIPPED rewrite (0 virtualized, no injection target) - " +
                        "dex passed through unchanged")
                log(onLog, "    VMC layout: EMPTY (header only, 112 bytes)")
            }
        }
        if (skips.floorSkipped.isNotEmpty()) {
            val shown = skips.floorSkipped.take(8).joinToString()
            log(onLog, "  size floor (< ${policy.minInsnsUnits} units): " +
                    "${skips.floorSkipped.size} method(s) left native: $shown" +
                    (if (skips.floorSkipped.size > 8) " ..." else ""))
        }
        if (skips.frameSkipped.isNotEmpty()) {
            val shown = skips.frameSkipped.take(8).joinToString()
            log(onLog, "  bad frame (ins beyond regs): " +
                    "${skips.frameSkipped.size} method(s) left native: $shown" +
                    (if (skips.frameSkipped.size > 8) " ..." else ""))
        }
        if (skips.unsupportedOpcodeSkipped.isNotEmpty()) {
            val shown = skips.unsupportedOpcodeSkipped.take(8).joinToString()
            log(onLog, "  unsupported interpreter opcode: " +
                    "${skips.unsupportedOpcodeSkipped.size} method(s) left native: $shown" +
                    (if (skips.unsupportedOpcodeSkipped.size > 8) " ..." else ""))
        }
        if (totalVirtualized == 0) {
            error("No methods were selected for virtualization; the pre-VM " +
                    "safety closure or whitelist protected the entire input")
        }

        var replacementApplicationName: String? = null
        if (standaloneApplicationLoader) {
            val loaderDex = DexRewriter.buildLoaderDex(
                loaderClass = loaderClassDesc,
                applicationClass = appClassDesc!!,
                libName = libName,
                debugMode = debugMode
            ) { log(onLog, "  $it") }
            val loaderDexName = "classes${dexNames.size + 1}.dex"
            dexNames.add(loaderDexName)
            newDexes.add(loaderDex)
            val loaderVmc = emptyVmcContainer()
            dexPlans.add(DexPlan(
                name = loaderDexName, inputBytes = loaderDex.size,
                candidateMethods = 0, virtualizedMethods = 0,
                vmcBytes = loaderVmc.size, rewritten = true,
                skipReason = "standalone loader dex"
            ))
            vmcs.add(loaderVmc)
            totalVmcBytes += loaderVmc.size
            replacementApplicationName = loaderClassSlash.replace('/', '.')
            log(onLog, "Added standalone loader $loaderDexName for ${targets.applicationClass}")
        }
        log(onLog, "VMC total: $totalVmcBytes bytes across ${vmcs.size} container(s)")

        val patched = AxmlPatcher.patch(manifestBytes, replacementApplicationName)
        log(onLog, when {
            replacementApplicationName != null ->
                "Manifest: Application replaced with $replacementApplicationName; " +
                        "loader delegates to ${targets.applicationClass} " +
                        "(extractNativeLibs=${patched.extractNativeLibs})"
            appClassDesc != null ->
                "Manifest: original Application kept (${targets.applicationClass}); " +
                        "initVM injected into its attachBaseContext " +
                        "(extractNativeLibs=${patched.extractNativeLibs})"
            else ->
                "Manifest: untouched (no Application class); " +
                        "initVM injected into ${componentDescs.size} component attachBaseContexts " +
                        "(extractNativeLibs=${patched.extractNativeLibs})"
        })
        if (patched.allowBackupDisabled)
            log(onLog, "  Manifest: android:allowBackup flipped to false (hardening)")
        else if (!patched.allowBackupPresent)
            log(onLog, "  WARNING: manifest has no explicit android:allowBackup; " +
                    "backup behavior remains platform-defined")

        log(onLog, "Loading libVMP for ABIs: ${abis.joinToString()}")
        val missingAbis = ArrayList<String>()
        val libVmpEntries = abis.mapNotNull { abi ->
            val bytes = soBytesByAbi[abi]
            if (bytes == null) {
                missingAbis.add(if (AbiPreflight.vmcAssetFor(abi) == null)
                    "$abi - no libVMP build exists for this ABI"
                else "${AbiPreflight.vmcAssetFor(abi)} - $abi missing from packer assets")
                null
            } else {
                log(onLog, "  $abi: ${bytes.size} bytes")
                LibEntry(abi, bytes)
            }
        }
        if (missingAbis.isNotEmpty())
            error(AbiPreflight.refusal(missingAbis))

        val userTag = identityTag?.trim()?.takeIf { it.isNotEmpty() }
        val idPkg = targets.manifestPackage?.takeIf { it.isNotBlank() }
            ?: appClassFqcn?.substringBeforeLast('.')?.takeIf { it.isNotBlank() }
        val effTag = userTag ?: idPkg?.let { "auto:$it" }
        val signer = signingSource?.let { ApkSigner.resolveSigner(ctx, it) }
            ?: ApkSigner.resolveSigner(ctx, effTag)
        val certPin: ByteArray =
            java.security.MessageDigest.getInstance("SHA-256").digest(signer.certDer)
        log(onLog, "Signing identity: " + when (val source = signingSource) {
            is SigningSource.ImportedJks -> "custom JKS '${source.alias}'"
            else -> when {
                userTag != null -> "named '$userTag'"
                idPkg != null -> "per-app '$idPkg'"
                else -> "EPHEMERAL (no package in manifest)"
            }
        })

        val finalPlan = PackPlan(
            abis = abis,
            loaderDex = if (standaloneApplicationLoader) dexNames.lastOrNull()
                        else dexNames.getOrNull(loaderDexIndex),
            standaloneLoader = standaloneApplicationLoader,
            componentHooks = componentDescs,
            skippedComponents = invalidComponentClasses,
            dexes = dexPlans,
            totalCandidates = totalCandidates,
            totalVirtualized = totalVirtualized,
            totalVmcBytes = totalVmcBytes
        )
        emit(onEvent, PackEvent(PackPhase.BUILD, message = "Building APK", plan = finalPlan))

        val unsigned = File(cacheDir, "unsigned.apk")
        ApkBuilder.build(
            input = input,
            output = unsigned,
            newDexes = newDexes,
            dexNames = dexNames,
            newManifest = patched.bytes,
            vmcs = vmcs,
            libVmpEntries = libVmpEntries,
            extractNativeLibs = patched.extractNativeLibs,
            libName = libName,
            loaderClassSlash = loaderClassSlash,
            certPin = certPin,
            assetName = containerAsset,
            runtimeCap = cap
        ) { log(onLog, "  $it") }

        val dest = outputDir(ctx, onLog)
        val pkgForName = idPkg
        val rawName = outName?.takeIf { it.isNotBlank() }
        if (rawName != null && !OutputNamePolicy.isSafeFileName(rawName)) {
            error("outName must be a safe APK basename: '$rawName'")
        }
        val finalName = rawName
            ?: OutputNamePolicy.fromPackage(pkgForName)
            ?: "protected.apk"
        val target = File(dest, finalName)
        val outputRoot = dest.canonicalFile
        require(target.canonicalFile.parentFile == outputRoot) {
            "output target must remain inside the app-owned output directory"
        }
        currentCoroutineContext().ensureActive()
        emit(onEvent, PackEvent(PackPhase.SIGN, message = "Signing APK", plan = finalPlan))
        ApkSigner.sign(unsigned, target, signer)
        val out = target
        log(onLog, "SIGNED APK: ${target.absolutePath} (${target.length()} bytes)")
        emit(onEvent, PackEvent(PackPhase.COMPLETE,
                message = "Pack complete", plan = finalPlan))

        out
    }

    /** Per-package preview of what pack() would virtualize: the same whitelist,
     *  grouped by package, streamed straight from the Uri. UI exclusions come
     *  back to pack() as excludeLines ("!path" lines). */
    class ScanResult(
        val manifestPackage: String?,
        val pkgPaths: List<String>,
        val pkgCounts: IntArray,
        val totalMethods: Int,
        /** pkgPath -> [(classPath, virtualizableMethodCount)], sorted by count.
         *  Deliberately NOT cached: it is the largest thing a scan produces and
         *  would change every cache key. Empty on a hit; the preview re-scans with
         *  forceFresh. */
        val classCounts: Map<String, List<Pair<String, Int>>> = emptyMap(),
        val plan: PackPlan? = null
    )

    suspend fun scanPackages(
        ctx: Context,
        inputUri: Uri,
        /** Bypass the cache and re-parse (classCounts is not persisted).
         *  Declared BEFORE onLog on purpose: a trailing lambda always binds to the
         *  LAST parameter, so any further defaulted parameter must also precede it. */
        forceFresh: Boolean = false,
        packageFilter: String? = null,
        /** Saved class/method exclusions for this scan policy. */
        excludeLines: List<String> = emptyList(),
        /** Optional ProGuard/R8 mapping for the exact input APK build. */
        mapping: ProguardMapping? = null,
        onEvent: ((PackEvent) -> Unit)? = null,
        onLog: (String) -> Unit
    ): ScanResult = withContext(Dispatchers.IO) {
        var manifestBytes: ByteArray? = null
        val dexesByName = LinkedHashMap<String, ByteArray>()
        val apkCrc = java.util.zip.CRC32()
        val apkSha = java.security.MessageDigest.getInstance("SHA-256")
        ctx.contentResolver.openInputStream(inputUri)?.use { ins ->
            val bounded = LimitedInputStream(ins, MAX_APK_BYTES)
            val hashed = java.security.DigestInputStream(bounded, apkSha)
            val checked = java.util.zip.CheckedInputStream(hashed, apkCrc)
            java.util.zip.ZipInputStream(checked.buffered()).use { zis ->
                var e = zis.nextEntry
                while (e != null) {
                    val n = e.name
                    if (n == "AndroidManifest.xml") {
                        manifestBytes = ApkUtil.readLimited(zis, MAX_ZIP_ENTRY_BYTES)
                    } else if (Regex("classes\\d*\\.dex").matches(n)) {
                        dexesByName[n] = ApkUtil.readLimited(zis, MAX_ZIP_ENTRY_BYTES)
                    }
                    e = zis.nextEntry
                }
            }
        } ?: error("Cannot open input APK")
        val manifest = manifestBytes ?: error("Input APK has no AndroidManifest.xml")
        val dexes = ArrayList<Pair<String, ByteArray>>()
        var dexIndex = 0
        while (true) {
            val name = if (dexIndex == 0) "classes.dex" else "classes${dexIndex + 1}.dex"
            val bytes = dexesByName[name] ?: break
            dexes.add(name to bytes)
            dexIndex++
        }
        val selectedNames = dexes.mapTo(HashSet()) { it.first }
        val nonContiguous = dexesByName.keys.filter { it !in selectedNames }
        if (nonContiguous.isNotEmpty()) {
            error("Input APK has non-contiguous dex entries: ${nonContiguous.joinToString()}")
        }
        val fileCrc = apkCrc.value

        val targets = AxmlPatcher.readTargets(manifest)
        if (mapping != null) {
            onLog("scan: mapping ${mapping.classCount} classes, fingerprint=${mapping.fingerprint.take(12)}")
            mapping.warnings.forEach { onLog("scan: mapping warning: $it") }
        }
        val definedClasses = if (mapping == null) {
            emptySet<String>()
        } else collectDefinedClasses(dexes.map { it.second })

        val policyLines = excludeLines.toList()
        val shaHex = apkSha.digest().joinToString("") { "%02x".format(it) }
        val cacheKey = ScanCacheKey.of(
                shaHex, fileCrc, policyLines, mapping?.fingerprint)
        if (!forceFresh && excludeLines.isEmpty()) {
            ScanCache.load(ctx)[cacheKey]?.let { e ->
                dexes.clear()
                log(onLog, "scan cache hit: ${e.paths.size} package(s), ${e.total} " +
                        "methods (APK + policy unchanged since last scan)")
                return@withContext ScanResult(e.pkg, e.paths, e.counts.toIntArray(),
                        e.total, emptyMap())
            }
        }

        val discoveryPolicy = deriveWhitelist(
                targets, emptyList(), mapping, onLog)
        val activePolicy = if (excludeLines.isEmpty()) discoveryPolicy else
            deriveWhitelist(targets, excludeLines, mapping) { }
        val scanAppClass = resolveMappedDescriptor(
                applicationDescriptor(targets), mapping, definedClasses)
        val invalidComponentClasses = if (scanAppClass == null) {
            val componentClasses = targets.contextComponentClasses
                .mapNotNull { resolveComponentName(it, targets.manifestPackage) }
                .map { "L${it.replace('.', '/')};" }
                .mapNotNull { resolveMappedDescriptor(it, mapping, definedClasses) }
            val supers = collectClassSuperclasses(dexes.map { it.second })
            val finalAttachBases = collectFinalAttachBases(dexes.map { it.second })
            componentClasses.filterNot {
                hasResolvableContextBase(it, supers, finalAttachBases)
            }
        } else emptyList()
        val discoveryEffectivePolicy = if (invalidComponentClasses.isEmpty()) {
            discoveryPolicy
        } else {
            onLog("  scan: excluding ${invalidComponentClasses.size} component(s) with unresolved or final superclasses")
            discoveryPolicy.copy(
                excludeClassPrefixes = discoveryPolicy.excludeClassPrefixes + invalidComponentClasses
            )
        }
        val activeEffectivePolicy = if (invalidComponentClasses.isEmpty()) {
            activePolicy
        } else {
            activePolicy.copy(
                excludeClassPrefixes = activePolicy.excludeClassPrefixes + invalidComponentClasses
            )
        }
        val scanEarlyClasses = HashSet<String>()
        scanAppClass?.let { scanEarlyClasses.add(it) }
        targets.componentClasses
            .mapNotNull { resolveComponentName(it, targets.manifestPackage) }
            .map { "L${it.replace('.', '/')};" }
            .filter { !VirtualizationPolicy.isLibraryClass(it) }
            .mapNotNull { resolveMappedDescriptor(it, mapping, definedClasses) }
            .forEach { scanEarlyClasses.add(it) }
        val scanClinitKeys = ClinitScan.clinitExemptKeys(
            dexes.map { it.second }, scanEarlyClasses, discoveryEffectivePolicy,
            { onLog(it) }
        )
        val scanPolicy = discoveryEffectivePolicy.withClinitExempt(scanClinitKeys)
        val activeScanPolicy = activeEffectivePolicy.withClinitExempt(scanClinitKeys)
        val scanSkips = SkipLog()
        val pkgCounts = LinkedHashMap<String, Int>()
        val classCounts = LinkedHashMap<String, LinkedHashMap<String, Int>>()
        var total = 0
        val dexPlans = ArrayList<DexPlan>()
        for ((index, item) in dexes.withIndex()) {
            currentCoroutineContext().ensureActive()
            val name = item.first
            val bytes = item.second
            if (packageFilter != null) {
                val hasPackageClass = DexBackedDexFile(Opcodes.forApi(34), bytes)
                    .classes.any { classDef ->
                        val display = mapping?.primaryOriginalDescriptorForObfuscated(classDef.type)
                            ?: classDef.type
                        display.startsWith("L$packageFilter/")
                    }
                if (!hasPackageClass) continue
            }
            emit(onEvent, PackEvent(PackPhase.SCAN,
                    message = "Parsing $name", current = index + 1, total = dexes.size))
            onLog("scan: parsing $name (${bytes.size / 1024} KB)...")
            val parser = DexParser(bytes, scanPolicy, scanSkips)
            val keys = parser.virtualizableKeys()
            val activeKeys = if (excludeLines.isEmpty()) keys
                             else parser.virtualizableKeys(activeScanPolicy)
            total += activeKeys.size
            if (packageFilter == null) {
                dexPlans.add(DexPlan(
                    name = name, inputBytes = bytes.size,
                    candidateMethods = keys.size, virtualizedMethods = activeKeys.size,
                    vmcBytes = 0, rewritten = false,
                    skipReason = if (activeKeys.isEmpty()) "no selected methods" else "preview"
                ))
            }
            for (k in keys) {
                val cls = k.substringBefore('|')
                val displayDesc = mapping?.primaryOriginalDescriptorForObfuscated(cls) ?: cls
                val path = displayDesc.removePrefix("L").removeSuffix(";")
                val pkg = if ('/' in path) path.substringBeforeLast('/') else "(default)"
                pkgCounts[pkg] = (pkgCounts[pkg] ?: 0) +
                        if (k in activeKeys) 1 else 0
                val cm = classCounts.getOrPut(pkg) { LinkedHashMap() }
                cm[path] = (cm[path] ?: 0) + 1
            }
            onLog("scan $name: ${activeKeys.size} methods would be virtualized")
        }
        val sorted = pkgCounts.entries.sortedByDescending { it.value }
        val classes = LinkedHashMap<String, List<Pair<String, Int>>>()
        for ((pkg, cm) in classCounts) {
            classes[pkg] = cm.entries.sortedByDescending { it.value }
                    .map { it.key to it.value }
        }
        val result = ScanResult(
            targets.manifestPackage,
            sorted.map { it.key },
            IntArray(sorted.size) { sorted[it].value },
            total,
            classes,
            if (packageFilter == null) PackPlan(
                abis = emptyList(), loaderDex = null, standaloneLoader = false,
                componentHooks = emptyList(), skippedComponents = invalidComponentClasses,
                dexes = dexPlans, totalCandidates = total,
                totalVirtualized = total, totalVmcBytes = 0
            ) else null
        )
        if (packageFilter == null && excludeLines.isEmpty()) {
            ScanCache.put(ctx, cacheKey, result)
            log(onLog, "scan cached for instant re-scan")
        }
        result
    }

    private val CONTEXT_BASE_CLASSES = setOf(
        "Landroid/content/ContextWrapper;",
        "Landroid/app/Application;",
        "Landroid/app/Activity;",
        "Landroid/app/Service;",
        "Landroid/app/ActivityGroup;",
        "Landroid/app/TabActivity;"
    )

    private fun collectDefinedClasses(dexes: List<ByteArray>): Set<String> {
        val result = HashSet<String>()
        for (bytes in dexes) {
            val dex = DexBackedDexFile(Opcodes.forApi(34), bytes)
            dex.classes.forEach { result.add(it.type) }
        }
        return result
    }

    /**
     * Resolve a source/manifest descriptor to the descriptor actually present
     * in DEX. A mapping record is never trusted by itself: the candidate must be
     * present in this APK, otherwise the old unresolved-class behavior remains.
     */
    private fun resolveMappedDescriptor(
        sourceDescriptor: String?,
        mapping: ProguardMapping?,
        definedClasses: Set<String>
    ): String? {
        if (sourceDescriptor == null || mapping == null) return sourceDescriptor
        if (sourceDescriptor in definedClasses) return sourceDescriptor
        return mapping?.obfuscatedDescriptorsForOriginal(sourceDescriptor)
            ?.firstOrNull { it in definedClasses }
            ?: sourceDescriptor
    }

    private fun collectClassSuperclasses(dexes: List<ByteArray>): Map<String, String?> {
        val result = HashMap<String, String?>()
        for (bytes in dexes) {
            val dex = DexBackedDexFile(Opcodes.forApi(34), bytes)
            for (classDef in dex.classes) {
                if (classDef.type !in result) result[classDef.type] = classDef.superclass
            }
        }
        return result
    }

    private fun collectFinalAttachBases(dexes: List<ByteArray>): Set<String> {
        val result = HashSet<String>()
        for (bytes in dexes) {
            val dex = DexBackedDexFile(Opcodes.forApi(34), bytes)
            for (classDef in dex.classes) {
                if (classDef.methods.any { method ->
                        method.name == "attachBaseContext" &&
                                method.returnType == "V" &&
                                method.parameters.size == 1 &&
                                method.parameters[0].type == "Landroid/content/Context;" &&
                                (method.accessFlags and 0x10) != 0
                    }) {
                    result.add(classDef.type)
                }
            }
        }
        return result
    }

    private fun hasResolvableContextBase(
        descriptor: String,
        superclasses: Map<String, String?>,
        finalAttachBases: Set<String>
    ): Boolean {
        val seen = HashSet<String>()
        var current: String? = descriptor
        while (current != null && seen.add(current)) {
            val parent = superclasses[current] ?: return false
            if (parent in finalAttachBases) return false
            if (parent in CONTEXT_BASE_CLASSES) return true
            current = parent
        }
        return false
    }

    private fun applicationDescriptor(targets: ManifestTargets): String? {
        val name = targets.applicationClass?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val fqcn = when {
            name.startsWith("L") && name.endsWith(";") -> return name
            name.startsWith(".") -> targets.manifestPackage?.let { it + name } ?: name
            !name.contains('.') -> targets.manifestPackage?.let { "$it.$name" } ?: name
            else -> name
        }
        return "L${fqcn.replace('.', '/')};"
    }

    private fun isFinalClass(bytes: ByteArray, descriptor: String): Boolean {
        val dex = DexBackedDexFile(Opcodes.forApi(34), bytes)
        val classDef = dex.classes.firstOrNull { it.type == descriptor } ?: return false
        return (classDef.accessFlags and 0x10) != 0
    }

    private fun locateLoaderDex(
        dexes: List<ByteArray>,
        candidates: Set<String>,
        loaderClass: String
    ): Int {
        var candidateDex = -1
        for ((index, bytes) in dexes.withIndex()) {
            val dex = DexBackedDexFile(Opcodes.forApi(34), bytes)
            var hasLoader = false
            var hasCandidate = false
            for (classDef in dex.classes) {
                if (classDef.type == loaderClass) hasLoader = true
                if (classDef.type in candidates) hasCandidate = true
            }
            if (hasLoader) {
                error("input dex already defines the loader class $loaderClass - repack to draw a different name")
            }
            if (candidateDex < 0 && hasCandidate) candidateDex = index
        }
        return candidateDex
    }

    /** Resolve a manifest android:name against <manifest package>, the way Android
     *  does. Null when a relative name has no package: guessing would virtualize
     *  the wrong class. */
    private fun resolveComponentName(cn: String, pkg: String?): String? = when {
        cn.startsWith(".") -> pkg?.let { it + cn }
        !cn.contains('.') -> pkg?.let { "$it.$cn" }
        else -> cn
    }

    /**
     * Shared whitelist derivation for pack() and scanPackages(), so the preview
     * uses the same method set as the pack.
     * Returns the value - nothing is installed anywhere.
     */
    private fun deriveWhitelist(
        targets: ManifestTargets,
        extraLines: List<String>,
        mapping: ProguardMapping?,
        onLog: (String) -> Unit
    ): PackPolicy {
        val pkg = targets.manifestPackage
        val seeds = targets.componentClasses
            .mapNotNull { resolveComponentName(it, pkg) }
            .map { "L${it.replace('.', '/')};" }
            .filter { !VirtualizationPolicy.isLibraryClass(it) }
            .distinct()
        if (seeds.isNotEmpty())
            onLog("  Component whitelist seeds: " + summarize(seeds))
        return PackPolicy.derive(
            targets.manifestPackage, targets.applicationClass,
            seeds + extraLines, mapping
        )
    }

    /**
     * The finished APK goes in the app's own external files dir, not Download/:
     * under scoped storage a file there keeps the UID that created it, so after a
     * packer reinstall the old output is permanently unwritable - while
     * File.canWrite() on the directory still returns true.
     */
    private fun outputDir(ctx: Context, onLog: (String) -> Unit): File {
        val dir = ctx.getExternalFilesDir(null) ?: ctx.cacheDir
        dir.mkdirs()
        log(onLog, "Output directory: ${dir.absolutePath}")
        return dir
    }

    fun cleanupCancelledPack(ctx: Context) {
        val dir = File(ctx.cacheDir, "vmpack")
        File(dir, "unsigned.apk").delete()
    }

    private fun emit(onEvent: ((PackEvent) -> Unit)?, event: PackEvent) {
        onEvent?.invoke(event)
    }

    private fun summarize(values: Collection<String>, limit: Int = 20): String {
        val shown = values.take(limit).joinToString(", ")
        return if (values.size > limit) {
            "$shown, ... (${values.size} total)"
        } else {
            shown
        }
    }

    private fun log(onLog: (String) -> Unit, message: String) {
        onLog(message)
    }
}

