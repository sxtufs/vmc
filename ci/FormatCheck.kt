import com.vmp.packer.AbiPreflight
import com.vmp.packer.AxmlPatcher
import com.vmp.packer.OutputNamePolicy
import com.vmp.packer.ApkUtil
import com.vmp.packer.DexPlan
import com.vmp.packer.PackEvent
import com.vmp.packer.PackPhase
import com.vmp.packer.PackPlan
import com.vmp.packer.LimitedInputStream
import com.vmp.packer.DexParser
import com.vmp.packer.DexPostProcessor
import com.vmp.packer.DexRewriter
import com.vmp.packer.InsnPerm
import com.vmp.packer.InterpreterOpcodePolicy
import com.vmp.packer.PackConfig
import com.vmp.packer.PackIdentity
import com.vmp.packer.PackPolicy
import com.vmp.packer.ProguardMapping
import com.vmp.packer.SkipLog
import com.vmp.packer.ScanCacheKey
import com.vmp.packer.RuntimeCapabilityProbe
import com.vmp.packer.VirtualizationPolicy
import com.vmp.packer.VmcWriter
import java.io.ByteArrayInputStream
import java.io.File
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

/**
 * Format checks for the pure-JVM half of the packer (DexParser,
 * VirtualizationPolicy, VmcWriter, InsnPerm, DexRewriter), run against a real
 * dex built from ci/TestSubject.kt.
 *
 * This is NOT a build check: each assertion here maps to a class of bug that
 * compiled cleanly and was only ever caught by an install-time verifier.
 * Non-zero exit on any FAIL.
 */

var passed = 0
var failed = 0

fun check(name: String, cond: Boolean, detail: String = "") {
    if (cond) { passed++; println("  PASS  $name") }
    else { failed++; println("  FAIL  $name  ${if (detail.isNotEmpty()) "[" + detail + "]" else ""}") }
}

fun i32(b: ByteArray, o: Int): Int =
    (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
            ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

/**
 * Structural verifier for an emitted dex - what ART's class-loader verifier does
 * at install time and what dexlib2 (which lazily DECODES but never VALIDATES)
 * cannot:
 *  - every instruction decodes without throwing,
 *  - every invoke's argument-register count matches the referenced signature,
 *  - 3rc ranges stay inside the method's register budget.
 * Skips only exotic families (invoke-custom/polymorphic; filled-new-array,
 * where regCount counts elements, not parameters).
 */
fun verifyDex(tag: String, bytes: ByteArray): Int {
    var problems = 0
    val df = DexBackedDexFile(Opcodes.forApi(34), bytes)
    for (cls in df.classes) {
        for (m in cls.methods) {
            val impl = m.implementation as com.android.tools.smali.dexlib2.iface.MethodImplementation?
                ?: continue
            val regs = impl.registerCount
            for (ins in impl.instructions) {
                val opcode = ins.opcode
                val name = opcode.name
                val ref = (ins as? ReferenceInstruction)?.reference
                if (ref is MethodReference && name.startsWith("INVOKE_") &&
                    !name.contains("POLYMORPHIC") && !name.contains("CUSTOM")) {
                    val parameterWords = ref.parameterTypes.sumOf { type ->
                        if (type == "J" || type == "D") 2 else 1
                    }
                    val wants = parameterWords +
                            (if (opcode != Opcode.INVOKE_STATIC) 1 else 0)
                    when (ins) {
                        is RegisterRangeInstruction -> {
                            if (ins.registerCount != wants) {
                                println("    $tag ${cls.type}->${m.name}: ${opcode.name} registerCount=${ins.registerCount}, signature wants $wants")
                                problems++
                            }
                            if (ins.startRegister + ins.registerCount > regs) {
                                println("    $tag ${cls.type}->${m.name}: ${opcode.name} range exceeds budget $regs")
                                problems++
                            }
                        }
                        is FiveRegisterInstruction -> {
                            if (ins.registerCount != wants) {
                                println("    $tag ${cls.type}->${m.name}: ${opcode.name} registerCount=${ins.registerCount}, signature wants $wants")
                                problems++
                            }
                            if (ins.registerCount > regs) {
                                println("    $tag ${cls.type}->${m.name}: ${opcode.name} arg count exceeds budget $regs")
                                problems++
                            }
                        }
                        else -> {}
                    }
                }
            }
        }
    }
    return problems
}

fun outputNameCheck(name: String): Boolean = OutputNamePolicy.isSafeFileName(name)

fun main(args: Array<String>) {
    check("output names reject traversal", !outputNameCheck("../../escape.apk"))
    check("output names accept a safe APK basename", outputNameCheck("com.example.app.apk"))
    check("manifest-derived names reject path components",
            OutputNamePolicy.fromPackage("../escape") == null)
    check("malformed AXML is rejected before string-pool allocation",
            runCatching { AxmlPatcher.readTargets(ByteArray(64)) }.isFailure)
    check("bounded input reader accepts data at the limit",
            ApkUtil.readLimited(ByteArrayInputStream(byteArrayOf(1, 2, 3)), 3)
                    .contentEquals(byteArrayOf(1, 2, 3)))
    check("bounded input reader rejects data over the limit",
            runCatching {
                ApkUtil.readLimited(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4)), 3)
            }.exceptionOrNull() is IllegalArgumentException)
    check("streaming input limit accepts exactly the whole limit",
            LimitedInputStream(ByteArrayInputStream(byteArrayOf(1, 2, 3)), 3)
                    .readBytes().contentEquals(byteArrayOf(1, 2, 3)))
    check("streaming input limit rejects oversized APK streams",
            runCatching {
                LimitedInputStream(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4)), 3)
                        .readBytes()
            }.exceptionOrNull() is IllegalArgumentException)
    val coveragePlan = PackPlan(
        abis = listOf("arm64-v8a"), loaderDex = "classes.dex",
        standaloneLoader = false, componentHooks = listOf("Ldemo/Main;"),
        skippedComponents = emptyList(),
        dexes = listOf(DexPlan("classes.dex", 100, 4, 3, 512, true)),
        totalCandidates = 4, totalVirtualized = 3, totalVmcBytes = 512
    )
    val coverageEvent = PackEvent(
        phase = PackPhase.DEX, message = "classes.dex", current = 1, total = 2,
        plan = coveragePlan
    )
    check("pack events expose bounded progress",
            coverageEvent.progress == 0.5f && coverageEvent.plan?.totalVirtualized == 3)

    val fixture = File(args.singleOrNull() ?: error("usage: FormatCheck <classes.dex>"))
    val bytes = fixture.readBytes()
    println("== GOLDEN (JVM) == fixture ${bytes.size} bytes")

    val pkgs = HashSet<String>()
    for (cls in DexBackedDexFile(Opcodes.forApi(34), bytes).classes) {
        val t = cls.type
        if (t.length > 2 && t.startsWith("Lfixt")) pkgs.add(t.substring(1, t.lastIndexOf('/')))
    }
    check("fixture packages found", pkgs.isNotEmpty(), pkgs.joinToString())
    check("opcode policy rejects every modern fused-marker collision",
            listOf(
                "INVOKE_POLYMORPHIC",
                "INVOKE_POLYMORPHIC_RANGE",
                "INVOKE_CUSTOM",
                "INVOKE_CUSTOM_RANGE",
                "CONST_METHOD_HANDLE",
                "CONST_METHOD_TYPE"
            ).all { InterpreterOpcodePolicy.isUnsupportedOpcodeName(it) } &&
                    !InterpreterOpcodePolicy.isUnsupportedOpcodeName("ADD_INT") &&
                    !InterpreterOpcodePolicy.isUnsupportedOpcodeName("DIV_INT"))
    val interpreterSource = File("native/src/interpreter.cpp").readText()
    val verifierSource = File("native/src/vmp_apk_verify.cpp").readText()
    check("runtime uses full APK v2/v3 cryptographic verification",
            verifierSource.contains("computeContentDigest") &&
                    verifierSource.contains("verifyJavaSignature") &&
                    verifierSource.contains("V3_BLOCK_ID"))
    val axmlSource = File("app/src/main/java/com/vmp/packer/AxmlPatcher.kt").readText()
    val packerSource = File("app/src/main/java/com/vmp/packer/Packer.kt").readText()
    check("shipping packer has no mutable override-file switches",
            !packerSource.contains("allow_partial_abis") &&
                    !packerSource.contains("restrict_prefixes") &&
                    !packerSource.contains("include_prefixes") &&
                    !packerSource.contains("no_prune") &&
                    !packerSource.contains("fuse_mask") &&
                    !packerSource.contains("fuse_detail") &&
                    !packerSource.contains("min_insns"))
    check("AXML patch rejects shared string-pool offsets",
            axmlSource.contains("offsetReferences != 1"))
    check("native filled-new-array handles nested array descriptors",
            interpreterSource.contains("desc[1] == '['"))
    check("native interpreter tracks entered monitors for unwind cleanup",
            interpreterSource.contains("enteredMonitors") &&
                    interpreterSource.contains("MonitorExit"))
    check("native integer arithmetic uses explicit Java-width wrapping",
            interpreterSource.contains("wrapAdd32") &&
                    interpreterSource.contains("wrapMul64") &&
                    interpreterSource.contains("wrapNeg32"))
    val parser = DexParser(bytes, PackPolicy.derive(null, null, pkgs.toList()), SkipLog())
    check("DexParser parses fixture", parser.classDefCount() > 0,
            "classes=${parser.classDefCount()}")
    val mutf8 = VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 1))
        .encodeMutf8ForTest("\uD83D\uDE00")
    check("VMC encodes supplementary characters as JNI Modified UTF-8",
            mutf8.contentEquals(byteArrayOf(
                0xED.toByte(), 0xA0.toByte(), 0xBD.toByte(),
                0xED.toByte(), 0xB8.toByte(), 0x80.toByte()
            )), mutf8.joinToString(" ") { "%02x".format(it) })
    val oversizedTable = bytes.copyOf()
    for (i in 0 until 4) oversizedTable[0x38 + i] = 0x7f
    check("DexParser rejects oversized table counts before allocation",
            runCatching {
                DexParser(oversizedTable,
                        PackPolicy.derive(null, null, pkgs.toList()), SkipLog())
            }.exceptionOrNull() is IllegalArgumentException)
    check("input dex passes mini-verifier", verifyDex("in", bytes) == 0)

    val vkeys = parser.virtualizableKeys()
    check("whitelist matched fixture methods", vkeys.isNotEmpty(), "keys=${vkeys.size}")
    if (vkeys.isEmpty()) {
        println("FORMAT CHECK: $passed passed, $failed failed")
        kotlin.system.exitProcess(1)
    }

    val startsOk = runCatching {
        InsnPerm.collectStarts(bytes, vkeys) { parser.insnsSizeOf(it) }
    }
    check("perm walk agrees with binary parser (all methods)",
            startsOk.isSuccess, startsOk.exceptionOrNull()?.message ?: "")
    val starts = startsOk.getOrNull()
        ?: run {
            println("FORMAT CHECK: $passed passed, ${failed + 1} failed (aborted: no starts)")
            kotlin.system.exitProcess(1)
        }
    check("walk covers every virtualized method", starts.size == vkeys.size,
            "${starts.size}/${vkeys.size}")

    val denseW = VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 4))
    denseW.insnStarts = starts
    val denseVmc = denseW.build()
    val w = VmcWriter(parser, PackConfig(runtimeMaxContainerVersion = 5))
    w.insnStarts = starts
    val vmc = w.build()

    println("  info  sparse=${vmc.size} vs dense=${denseVmc.size} " +
            "(fixture too small for pruning to pay)")
    check("sparse feature bit is set", (i32(vmc, 20) and 1) != 0,
            "features=${i32(vmc, 20)}")
    check("dense baseline has no feature bit", (i32(denseVmc, 20) and 1) == 0,
            "features=${i32(denseVmc, 20)}")
    val pOff = i32(vmc, InsnPerm.PERM_OFF_SLOT)
    check("perm section emitted", pOff >= 112 && i32(vmc, 8) == vmc.size,
            "perm_off=$pOff size=${vmc.size}")

    val before = vmc.copyOf()
    val fwd = InsnPerm.applyToBlob(vmc, s2c = false)
    val changed = !vmc.contentEquals(before)
    val back = InsnPerm.applyToBlob(vmc, s2c = true)
    check("permute changes opcode bytes", fwd && changed, "fwd=$fwd changed=$changed")
    check("permute round-trips byte-exact", back && vmc.contentEquals(before), "back=$back")

    val postProcessAttempt = runCatching { DexPostProcessor.repairCodeItems(bytes) }
    check("post-processor walks try/catch code items", postProcessAttempt.isSuccess,
            postProcessAttempt.exceptionOrNull()?.message ?: "")

    val loaderDesc = "Lcom/zq41k/ae;"
    val rewriteAttempt = runCatching {
        DexRewriter.rewrite(
            bytes, parser, injectLoader = true, loaderClass = loaderDesc,
            libName = "g7x", debugMode = false
        ) { }
    }
    check("rewriter handles try/catch code items", rewriteAttempt.isSuccess,
            rewriteAttempt.exceptionOrNull()?.message ?: "")
    val missingApplicationAttempt = runCatching {
        DexRewriter.rewrite(
            bytes, parser, injectLoader = false, loaderClass = loaderDesc,
            appClassName = "Lfixt/MissingApplication;", libName = "g7x", debugMode = false
        ) { }
    }
    check("rewriter refuses a missing Application hook", missingApplicationAttempt.isFailure,
            missingApplicationAttempt.exceptionOrNull()?.message ?: "no refusal")
    val rewritten = rewriteAttempt.getOrElse {
        println("FORMAT CHECK: $passed passed, $failed failed (aborted: rewrite)")
        kotlin.system.exitProcess(1)
    }

    val rdOk = runCatching { DexBackedDexFile(Opcodes.forApi(34), rewritten) }.isSuccess
    check("emitted dex parses", rdOk)
    if (rdOk) {
        val probs = verifyDex("out", rewritten)
        check("emitted dex passes mini-verifier", probs == 0, "$probs problems")

        val rd = DexBackedDexFile(Opcodes.forApi(34), rewritten)
        val loader = rd.classes.firstOrNull { it.type == loaderDesc }
        check("loader class present", loader != null, loaderDesc)
        if (loader != null) {
            val names = loader.methods.map { it.name }.toSet()
            check("loader has exactly the 4 expected methods",
                    names == setOf("<clinit>", "<init>", "initVM", "attachBaseContext"),
                    names.joinToString())
            val iv = loader.methods.firstOrNull { it.name == "initVM" }
            val af = iv?.accessFlags ?: -1
            check("initVM is static + native",
                    iv != null && (af and 0x1) == 0x1 && (af and 0x100) == 0x100,
                    "flags=0x${Integer.toHexString(af)}")
            check("initVM signature = (AssetManager, I, Z, Context) -> V",
                    iv != null &&
                    iv.parameters.map { it.type } == listOf(
                        "Landroid/content/res/AssetManager;", "I", "Z",
                        "Landroid/content/Context;") && iv.returnType == "V")
            val loaderAttachRefs = loader.methods.firstOrNull { it.name == "attachBaseContext" }
                ?.implementation?.instructions
                ?.mapNotNull { (it as? ReferenceInstruction)?.reference as? MethodReference }
                ?: emptyList()
            val loaderSuper = loaderAttachRefs.indexOfFirst {
                it.name == "attachBaseContext" && it.definingClass == "Landroid/app/Application;"
            }
            val loaderAssets = loaderAttachRefs.indexOfFirst { it.name == "getAssets" }
            val loaderInit = loaderAttachRefs.indexOfFirst {
                it.name == "initVM" && it.definingClass == loaderDesc
            }
            check("loader registers VM before entering application attachBaseContext",
                    loaderAssets >= 0 && loaderInit > loaderAssets &&
                    loaderSuper > loaderInit,
                    "assets=$loaderAssets init=$loaderInit super=$loaderSuper")
        }
    }


    val noHook = DexRewriter.rewrite(
        bytes, parser, injectLoader = false, loaderClass = loaderDesc,
        appClassName = "Lfixt/Base;", libName = "g7x", debugMode = false
    ) { }
    val baseCls = DexBackedDexFile(Opcodes.forApi(34), noHook)
        .classes.firstOrNull { it.type == "Lfixt/Base;" }
    check("non-Context target gains no attachBaseContext",
            baseCls != null && baseCls.methods.none { it.name == "attachBaseContext" },
            baseCls?.methods?.joinToString { it.name } ?: "class missing")
    check("9a dex passes mini-verifier", verifyDex("9a", noHook) == 0)

    val guardedHook = DexRewriter.rewrite(
        bytes, parser, injectLoader = false, loaderClass = loaderDesc,
        componentClassDescs = listOf("Lfixt/TestSubject;"),
        libName = "g7x", debugMode = false
    ) { }
    val guardedCls = DexBackedDexFile(Opcodes.forApi(34), guardedHook)
        .classes.firstOrNull { it.type == "Lfixt/TestSubject;" }
    check("custom non-Context component gains no invalid hook",
            guardedCls != null && guardedCls.methods.none { it.name == "attachBaseContext" },
            guardedCls?.methods?.joinToString { it.name } ?: "class missing")
    check("9b dex passes mini-verifier", verifyDex("9b", guardedHook) == 0)

    run {
        val codeSize = i32(before, 68)
        val records = codeSize / 36
        check("code section is a whole number of 36-byte records",
                codeSize % 36 == 0, "codeSize=$codeSize")

        val expected = vkeys.filter { parser.midxOf(it) >= 0 }
        val noCode = expected.filter { parser.codeOf(it) == null }
        check("every virtualized key has a code item (no phantom records)",
                noCode.isEmpty(), "${noCode.size} key(s) without code: " +
                        noCode.take(3).joinToString())
        check("VMC code table holds one record per virtualized method",
                records == expected.size, "records=$records expected=${expected.size}")

        val dexNative = ArrayList<String>()
        for (cls in DexBackedDexFile(Opcodes.forApi(34), rewritten).classes) {
            if (cls.type == loaderDesc) continue
            for (m in cls.methods)
                if (m.accessFlags and 0x100 != 0) dexNative.add("${cls.type}->${m.name}")
        }
        val policyKeys = vkeys.map { k ->
            "${k.substringBefore('|')}->${k.split('|').getOrElse(1) { "" }}"
        }
        check("native stubs and code table cover the same number of methods",
                dexNative.size == records, "native=${dexNative.size} records=$records")
        check("native stubs and virtualized set are the SAME methods",
                dexNative.toSet() == policyKeys.toSet(),
                "onlyNative=" + (dexNative.toSet() - policyKeys.toSet()).take(3) +
                        " onlyVmc=" + (policyKeys.toSet() - dexNative.toSet()).take(3))
    }

    run {
        check("vmcAssetFor maps the four built ABIs and nulls the rest",
                AbiPreflight.vmcAssetFor("arm64-v8a") == "vmp/libVMP-arm64-v8a.so" &&
                        AbiPreflight.vmcAssetFor("armeabi-v7a") == "vmp/libVMP-armeabi-v7a.so" &&
                        AbiPreflight.vmcAssetFor("x86") == "vmp/libVMP-x86.so" &&
                        AbiPreflight.vmcAssetFor("x86_64") == "vmp/libVMP-x86_64.so" &&
                        AbiPreflight.vmcAssetFor("mips") == null)
        check("vmcAssetFor maps the four built ABIs and nulls the rest",
                AbiPreflight.vmcAssetFor("arm64-v8a") == "vmp/libVMP-arm64-v8a.so" &&
                        AbiPreflight.vmcAssetFor("armeabi-v7a") == "vmp/libVMP-armeabi-v7a.so" &&
                        AbiPreflight.vmcAssetFor("x86") == "vmp/libVMP-x86.so" &&
                        AbiPreflight.vmcAssetFor("x86_64") == "vmp/libVMP-x86_64.so" &&
                        AbiPreflight.vmcAssetFor("mips") == null)
        check("Java-only inputs default to every supported runtime ABI",
                AbiPreflight.DEFAULT_ABIS ==
                        listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86"))

        val uncov = AbiPreflight.uncovered(
                listOf("arm64-v8a", "x86", "mips"), listOf("libVMP-arm64-v8a.so"))
        check("uncovered reports the missing asset AND the unbuilt ABI",
                uncov.size == 2 && uncov[0].startsWith("x86:") &&
                        uncov[1].startsWith("mips:"), uncov.joinToString(" | "))
        check("full coverage produces no refusal lines",
                AbiPreflight.uncovered(
                        listOf("arm64-v8a", "x86"),
                        listOf("libVMP-arm64-v8a.so", "libVMP-x86.so")).isEmpty())
        check("refusal text makes partial ABI output impossible",
                AbiPreflight.refusal(uncov).contains("Packing is refused") &&
                        !AbiPreflight.refusal(uncov).contains("allow_partial_abis.txt"))

        val so10 = "junk\u0000vmp.abi.10\u0000more".toByteArray(Charsets.ISO_8859_1)
        val so8 = "vmp.abi.8".toByteArray(Charsets.ISO_8859_1)
        val noTok = "no token in this image".toByteArray(Charsets.ISO_8859_1)
        check("tokenOf finds the literal inside binary bytes (NUL-surrounded)",
                RuntimeCapabilityProbe.tokenOf(so10) == 10,
                "${RuntimeCapabilityProbe.tokenOf(so10)}")
        check("tokenOf returns null for a pre-token template",
                RuntimeCapabilityProbe.tokenOf(noTok) == null)

        val bothOk = RuntimeCapabilityProbe.probe(
                linkedMapOf("arm64-v8a" to so10, "x86" to so8))
        check("cap is the LOWEST answer, never the newest",
                bothOk.cap == 8 && bothOk.noToken.isEmpty(),
                "cap=${bothOk.cap}")

        val oneSilent = RuntimeCapabilityProbe.probe(
                linkedMapOf("arm64-v8a" to so10, "x86" to noTok))
        check("an ABI that answers nothing forces dense v1",
                oneSilent.cap == 1 && oneSilent.noToken == listOf("x86"),
                "cap=${oneSilent.cap} noToken=${oneSilent.noToken}")

        val partial = RuntimeCapabilityProbe.probe(
                linkedMapOf("arm64-v8a" to so10, "mips" to null))
        check("an absent ABI does not vote on the floor",
                partial.minCap == 10 && partial.cap == 1 &&
                        partial.noToken == listOf("mips"),
                "minCap=${partial.minCap} cap=${partial.cap}")
        check("requireFloor accepts the current contract",
                runCatching { RuntimeCapabilityProbe.requireFloor(partial) }.isSuccess)
        val refused = runCatching {
            RuntimeCapabilityProbe.requireFloor(
                    RuntimeCapabilityProbe.Result(6, emptyList<String>(),
                            InsnPerm.MULTI_PERM_CAP - 1))
        }.exceptionOrNull()
        check("requireFloor refuses a pre-contract template",
                refused is IllegalStateException &&
                        (refused.message ?: "").contains("predate the current container"),
                refused?.message ?: "no refusal raised")
        check("verdict reports the ceiling it decided on",
                RuntimeCapabilityProbe.verdict(bothOk, listOf("arm64-v8a", "x86"))
                        .contains("v8 -> sparse"),
                RuntimeCapabilityProbe.verdict(bothOk, listOf("arm64-v8a")))

        var widthsOk = true
        var bad = ""
        repeat(200) {
            val i = PackIdentity.draw()
            if ("lib${i.libName}.so".length != 9 ||
                    i.containerAsset.length > 10 ||
                    i.loaderClassSlash.length != 12 ||
                    i.loaderClassDesc != "L${i.loaderClassSlash};" ||
                    !Regex("com/[a-z][a-z0-9]{4}/[a-z][a-z0-9]").matches(i.loaderClassSlash) ||
                    !i.attachOrigName.startsWith("attachBaseContext_")) {
                widthsOk = false
                bad = "${i.libName}/${i.containerAsset}/${i.loaderClassSlash}"
            }
        }
        check("200 identity draws all fit their .so patch slots", widthsOk, bad)
        val drawn = (1..50).map { PackIdentity.draw().loaderClassSlash }.toSet()
        check("identity is not repeated across packs", drawn.size == 50,
                "${drawn.size}/50 distinct")
    }

    run {
        val mappingText = """
            # {"id":"com.android.tools.r8.mapping","version":"2.0"}
            com.example.app.Main -> a.b:
                1:3:void doThing():10:12 -> c
                void keep() -> d
            com.example.app.feature.Work -> a.c: # {"id":"sourceFile","fileName":"Work.kt"}
                1:1:void run():5:5 -> e
            # {"id":"com.android.tools.r8.synthesized"}
        """.trimIndent()
        val mapping = ProguardMapping.parse(mappingText)
        check("mapping: class records are parsed", mapping.classCount == 2,
                "${mapping.classCount}")
        check("mapping: R8 version comments do not become records",
                mapping.warnings.isEmpty(), mapping.warnings.toString())
        check("mapping: obfuscated descriptor resolves to original descriptor",
                mapping.originalDescriptorsForObfuscated("La/b;") ==
                        listOf("Lcom/example/app/Main;"),
                mapping.originalDescriptorsForObfuscated("La/b;").toString())
        check("mapping: original descriptor resolves to obfuscated descriptor",
                mapping.obfuscatedDescriptorsForOriginal("Lcom/example/app/feature/Work;") ==
                        listOf("La/c;"),
                mapping.obfuscatedDescriptorsForOriginal("Lcom/example/app/feature/Work;").toString())
        check("mapping: member records retain original method names",
                mapping.originalMethodNamesForObfuscated("La/b;", "c") == setOf("doThing"),
                mapping.originalMethodNamesForObfuscated("La/b;", "c").toString())
        check("mapping: raw-content fingerprints are deterministic and sensitive",
                mapping.fingerprint == ProguardMapping.parse(mappingText).fingerprint &&
                        mapping.fingerprint != ProguardMapping.parse(mappingText + "\\n").fingerprint)
        val mappedPolicy = PackPolicy.derive(
                "com.example.app", null,
                listOf("!com.example.app.Main->doThing"), mapping)
        check("mapping policy: an obfuscated app class matches its source package",
                mappedPolicy.isTargetAppClass("La/b;"))
        check("mapping policy: source package does not match an unrelated class",
                !mappedPolicy.isTargetAppClass("Lother/X;"))
        check("mapping policy: source method exclusion reaches its obfuscated name",
                !mappedPolicy.shouldVirtualize(
                        "La/b;", "c", "", "V", false, false,
                        instructionCount = 20, registersSize = 8, insSize = 4,
                        outsSize = 2, skips = SkipLog()))
        check("mapping policy: no mapping preserves obfuscated-only behavior",
                !PackPolicy.derive("com.example.app", null)
                        .isTargetAppClass("La/b;"))
        check("mapping: empty input is rejected",
                runCatching { ProguardMapping.parse("# only comments") }.isFailure)
        check("mapping: malformed UTF-free text with no class records is rejected",
                runCatching { ProguardMapping.parse("not a mapping record") }.isFailure)
        val futureMapping = ProguardMapping.parse(
                """
                    #{"id":"com.android.tools.r8.mapping","version":"3.0"}
                    com.future.App -> q.a:
                """.trimIndent())
        check("mapping: future versions remain usable but warn",
                futureMapping.classCount == 1 && futureMapping.warnings.size == 1,
                futureMapping.warnings.toString())
        check("mapping: invalid UTF-8 is rejected before parsing",
                runCatching {
                    ProguardMapping.parseUtf8(byteArrayOf(0xC3.toByte(), 0x28))
                }.isFailure)

    }

    run {
        val wl = PackPolicy.derive("com.foo", "com.foo.App", listOf("other/pkg"))
        val none = PackPolicy.derive(null, null, listOf("# comment", "   "))

        check("derive: manifest package yields a descriptor prefix",
                wl.targetPrefixes.contains("Lcom/foo/"), wl.targetPrefixes.toString())
        check("derive: application class adds its own descriptor",
                wl.targetPrefixes.contains("Lcom/foo/App;"), wl.targetPrefixes.toString())
        check("derive: an extra prefix line is honoured",
                wl.targetPrefixes.contains("Lother/pkg/"), wl.targetPrefixes.toString())
        val exactSeed = PackPolicy.derive(null, null, listOf("Lcom/foo/Activity;"))
        check("derive: descriptor seeds match only the named class",
                exactSeed.isTargetAppClass("Lcom/foo/Activity;") &&
                        !exactSeed.isTargetAppClass("Lcom/foo/Other;"),
                exactSeed.targetPrefixes.toString())
        check("derive: a descriptor applicationClass keeps itself and its package",
                PackPolicy.derive(null, "Lal/a;", emptyList())
                        .targetPrefixes.containsAll(setOf("Lal/a;", "Lal/")))
        check("derive: nothing derivable falls back to the legacy blacklist",
                !none.targetsConfigured && none.isTargetAppClass("Lcom/any/Thing;") &&
                        !none.isTargetAppClass("Landroid/os/Bundle;"),
                "configured=${none.targetsConfigured}")
        check("whitelist: an app class matches",
                wl.isTargetAppClass("Lcom/foo/Bar;"))
        check("whitelist: a sibling package is not swept in",
                !wl.isTargetAppClass("Lcom/foobar/X;"), "prefix must end in /")

        val m = PackPolicy.derive(null, null,
                listOf("com.foo", "!com.foo.Bar->doThing"))
        check("exclude: method key keeps the descriptor semicolon",
                m.excludeMethods == setOf("Lcom/foo/Bar;->doThing"),
                m.excludeMethods.toString())
        check("exclude: a method line does not exclude the whole class",
                m.excludeClassPrefixes.isEmpty(), m.excludeClassPrefixes.toString())

        val c = PackPolicy.derive(null, null, listOf("com.foo", "!com.foo.Bar"))
        check("exclude: class form covers class, inner and package",
                c.excludeClassPrefixes ==
                        setOf("Lcom/foo/Bar;", "Lcom/foo/Bar$", "Lcom/foo/Bar/"),
                c.excludeClassPrefixes.toString())
        val descriptorExclude = PackPolicy.derive(null, null,
                listOf("Lcom/foo/Bar;", "!Lcom/foo/Bar;"))
        check("exclude: descriptor class form preserves the descriptor",
                descriptorExclude.excludeClassPrefixes ==
                        setOf("Lcom/foo/Bar;", "Lcom/foo/Bar$", "Lcom/foo/Bar/"),
                descriptorExclude.excludeClassPrefixes.toString())
        check("exclude: comment-only lines add nothing",
                PackPolicy.derive(null, null, listOf("com.foo", "#x", "")).let {
                    it.excludeClassPrefixes.isEmpty() && it.excludeMethods.isEmpty()
                })

        val sk = SkipLog()
        val base = PackPolicy.derive(null, null, listOf("com.foo"))
                .withMinInsnsUnits(5)
                .withClinitExempt(setOf("Lcom/foo/Early;->run"))

        fun q(p: PackPolicy, cls: String, name: String = "m", params: String = "",
              ret: String = "V", iface: Boolean = false, ctor: Boolean = false,
              units: Int = 20, regs: Int = 8, ins: Int = 4, outs: Int = 2,
              unsupportedOpcode: String? = null, s: SkipLog = sk): Boolean =
            p.shouldVirtualize(cls, name, params, ret, iface, ctor,
                    units, regs, ins, outs, s, unsupportedOpcode)

        check("rule: the named method is refused",
                !q(m, "Lcom/foo/Bar;", "doThing"))
        check("rule: its siblings in the same class still virtualize",
                q(m, "Lcom/foo/Bar;", "other"))
        check("rule: an excluded class's inner class is covered too",
                !q(c, "Lcom/foo/Bar\$Inner;"))
        check("rule: exclusion does not reach a prefix sibling",
                q(c, "Lcom/foo/Barxyz;"), "over-reach: Barxyz excluded")

        check("rule: a plain app method virtualizes", q(base, "Lcom/foo/A;"))
        check("rule: an interface method does not",
                !q(base, "Lcom/foo/A;", iface = true))
        check("rule: a constructor does not",
                !q(base, "Lcom/foo/A;", "<init>", ctor = true))
        check("rule: attachBaseContext is never virtualized",
                !q(base, "Lcom/foo/A;", "attachBaseContext"))
        check("rule: a Context->Context factory is not virtualized",
                !q(base, "Lcom/foo/A;", "wrap", params = "Landroid/content/Context;",
                        ret = "Landroid/content/ContextWrapper;"))
        check("rule: a <clinit>-reachable method stays out of the VM",
                !q(base, "Lcom/foo/Early;", "run"))
        check("rule: a class outside the whitelist is not virtualized",
                !q(base, "Lorg/other/B;"))
        check("rule: frame veto refuses ins beyond registers",
                !q(base, "Lcom/foo/A;", ins = 9, regs = 8))
        check("rule: outs beyond registers is a valid outgoing area",
                q(base, "Lcom/foo/A;", outs = 9, regs = 8))
        check("rule: a negative insns size is refused",
                !q(base, "Lcom/foo/A;", units = -1))
        check("rule: unsupported interpreter opcode stays native",
                !q(base, "Lcom/foo/A;", "modern", unsupportedOpcode = "INVOKE_CUSTOM"))
        for (modern in listOf(
                "INVOKE_POLYMORPHIC",
                "INVOKE_POLYMORPHIC_RANGE",
                "INVOKE_CUSTOM",
                "INVOKE_CUSTOM_RANGE",
                "CONST_METHOD_HANDLE",
                "CONST_METHOD_TYPE"
        )) {
            check("rule: $modern stays native",
                    !q(base, "Lcom/foo/A;", "modern", unsupportedOpcode = modern))
        }
        check("rule: a sub-floor method stays native",
                !q(base, "Lcom/foo/A;", units = 3))
        check("rule: the boolean one-liner is carved out of the floor",
                q(base, "Lcom/foo/A;", units = 3, ret = "Z"))
        check("rule: a boolean ARRAY getter is NOT carved out",
                !q(base, "Lcom/foo/A;", units = 3, ret = "[Z"))
        check("rule: floor 0 disables the floor",
                q(base.withMinInsnsUnits(0), "Lcom/foo/A;", units = 1))

        val sk2 = SkipLog()
        q(base, "Lcom/foo/A;", "small", units = 3, s = sk2)
        q(base, "Lcom/foo/A;", "alsoSmall", units = 1, s = sk2)
        q(base, "Lcom/foo/B;", "badFrame", ins = 9, regs = 8, s = sk2)
        q(base, "Lorg/other/C;", "notApp", units = 3, s = sk2)
        check("skips: floorSkipped counts only real candidates",
                sk2.floorSkipped == setOf("Lcom/foo/A;->small",
                        "Lcom/foo/A;->alsoSmall"), sk2.floorSkipped.toString())
        check("skips: frame veto is reported separately",
                sk2.frameSkipped == setOf("Lcom/foo/B;->badFrame"),
                sk2.frameSkipped.toString())
        val sk3 = SkipLog()
        q(base, "Lcom/foo/A;", "stillSmall", units = 2, s = sk3)
        check("skips: a fresh SkipLog does not inherit earlier declines",
                sk3.floorSkipped == setOf("Lcom/foo/A;->stillSmall") &&
                        sk3.frameSkipped.isEmpty(),
                "floor=${sk3.floorSkipped} frame=${sk3.frameSkipped}")
    }

    run {
        val sha = "ab".repeat(20)
        val pol = listOf("Lcom/foo/", "5")
        check("cache: the size floor is part of the key",
                ScanCacheKey.of(sha, 7L, listOf("Lcom/foo/", "5")) !=
                        ScanCacheKey.of(sha, 7L, listOf("Lcom/foo/", "0")),
                "a floor-only edit must miss the cache")
        check("cache: identical inputs reproduce the key",
                ScanCacheKey.of(sha, 7L, pol) == ScanCacheKey.of(sha, 7L, pol))
        check("cache: the APK digest is in the key",
                ScanCacheKey.of(sha, 7L, pol) != ScanCacheKey.of(sha + "cd", 7L, pol))
        check("cache: the APK content CRC is in the key",
                ScanCacheKey.of(sha, 7L, pol) != ScanCacheKey.of(sha, 8L, pol))
        check("cache: no policy files still hashes stable",
                ScanCacheKey.of(sha, 7L, emptyList()) == ScanCacheKey.of(sha, 7L, emptyList()))
        check("cache: a comment-only line still changes the key",
                ScanCacheKey.of(sha, 7L, listOf("# note")) !=
                        ScanCacheKey.of(sha, 7L, emptyList()))
        check("cache: key carries the schema and mapping slot",
                ScanCacheKey.of(sha, 7L, pol).split(':').size == 5,
                ScanCacheKey.of(sha, 7L, pol))
        check("cache: mapping fingerprints invalidate the scan",
                ScanCacheKey.of(sha, 7L, pol, "map-a") !=
                        ScanCacheKey.of(sha, 7L, pol, "map-b"))
        check("cache: absent and present mappings cannot collide",
                ScanCacheKey.of(sha, 7L, pol) !=
                        ScanCacheKey.of(sha, 7L, pol, "map-a"))
        check("cache: policy CRC is order-sensitive",
                ScanCacheKey.policyCrc(listOf("a", "b")) !=
                        ScanCacheKey.policyCrc(listOf("b", "a")))
        check("cache: policy line boundaries are part of the key",
                ScanCacheKey.policyCrc(listOf("ab", "c")) !=
                        ScanCacheKey.policyCrc(listOf("a", "bc")),
                "different line lists must not hash like their concatenation")
    }

    println("FORMAT CHECK: $passed passed, $failed failed")
    if (failed > 0) kotlin.system.exitProcess(1)
}
