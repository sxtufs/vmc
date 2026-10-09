package com.vmp.packer

import java.util.Collections
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.DexFile
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.MethodImplementation
import com.android.tools.smali.dexlib2.iface.instruction.*
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool

/**
 * Rewrites a DEX file with dexlib2. Every method PackPolicy accepts
 * gets ACC_NATIVE and loses its implementation, becoming a native stub with the
 * same signature; everything else keeps its body. With injectLoader, also adds
 * the loader class extending "Landroid/app/Application;".
 *
 * Hard constraint: the loader's randomised SLASH form "com/<5>/<2>" must be
 * exactly 12 bytes, the size of the kLoaderClass .rodata literal ApkBuilder
 * rewrites in the embedded .so. The native entry binds via RegisterNatives from
 * JNI_OnLoad, not Java_<class>_<method> export lookup: an in-place rename would
 * leave the .dynstr hash tables stale. Letter-initial [a-z0-9] segments keep it
 * a legal Java identifier.
 */
object DexRewriter {

    private const val SUPER_CLASS = "Landroid/app/Application;"
    private const val CONTEXT_CLASS = "Landroid/content/Context;"
    private const val ASSET_MANAGER_CLASS = "Landroid/content/res/AssetManager;"

    /** Known framework/library roots that declare attachBaseContext. */
    private val CONTEXT_ATTACH_BASES = setOf(
        "Landroid/content/ContextWrapper;",
        "Landroid/app/Application;",
        "Landroid/app/Activity;",
        "Landroid/app/Service;",
        "Landroid/app/ActivityGroup;",
        "Landroid/app/TabActivity;",
        "Landroidx/activity/ComponentActivity;",
        "Landroidx/fragment/app/FragmentActivity;",
        "Landroidx/appcompat/app/AppCompatActivity;"
    )

    /** True only when an injected invokesuper can resolve attachBaseContext. */
    private fun canInvokeAttachBaseContext(
        superClass: String?,
        classSuperclasses: Map<String, String?>
    ): Boolean {
        val seen = HashSet<String>()
        var current = superClass
        while (current != null && seen.add(current)) {
            if (current in CONTEXT_ATTACH_BASES) return true
            current = classSuperclasses[current]
        }
        return false
    }

    private val CTX_GET_ASSETS_REF = ImmutableMethodReference(
        CONTEXT_CLASS, "getAssets", emptyList(), ASSET_MANAGER_CLASS)
    private val NO_ANNOTATIONS: Set<com.android.tools.smali.dexlib2.iface.Annotation> = Collections.emptySet()
    private val NO_HIDDEN_RESTRICTIONS: Set<com.android.tools.smali.dexlib2.HiddenApiRestriction> = Collections.emptySet()

    private fun incomingWords(method: Method): Int {
        var words = if ((method.accessFlags and AccessFlags.STATIC.value) == 0) 1 else 0
        for (parameter in method.parameters) {
            words += if (parameter.type == "J" || parameter.type == "D") 2 else 1
        }
        return words
    }

    private fun maxReferencedRegister(implementation: MethodImplementation): Int {
        var max = -1
        for (instruction in implementation.instructions) {
            val highest = when (instruction) {
                is RegisterRangeInstruction ->
                    if (instruction.registerCount == 0) -1
                    else instruction.startRegister + instruction.registerCount - 1
                is FiveRegisterInstruction ->
                    maxOf(instruction.registerC, instruction.registerD,
                            instruction.registerE, instruction.registerF, instruction.registerG)
                is ThreeRegisterInstruction ->
                    maxOf(instruction.registerA, instruction.registerB, instruction.registerC)
                is TwoRegisterInstruction ->
                    maxOf(instruction.registerA, instruction.registerB)
                is OneRegisterInstruction -> instruction.registerA
                else -> -1
            }
            if (highest > max) max = highest
        }
        return max
    }

    /**
     * Materialize the implementation with an explicit register frame. This avoids
     * relying on DexBackedMethodImplementation's lazy frame when DexPool writes
     * a multidex output.
     */
    private fun normalizeImplementation(method: Method, implementation: MethodImplementation): MethodImplementation {
        val required = maxOf(incomingWords(method), maxReferencedRegister(implementation) + 1)
        val registerCount = maxOf(implementation.registerCount, required)
        return ImmutableMethodImplementation(
            registerCount,
            implementation.instructions,
            implementation.tryBlocks,
            implementation.debugItems
        )
    }

    /**
     * Verifies the frame that dexlib2 emitted for every remaining code body.
     * DexPool derives ins_size from the method signature, so this catches a
     * signature/frame mismatch before a device rejects the rewritten dex.
     */
    fun verifyIncomingFrames(bytes: ByteArray, label: String) {
        val file = DexBackedDexFile(Opcodes.forApi(34), bytes)
        for (classDef in file.classes) {
            for (method in classDef.methods) {
                val implementation = method.implementation ?: continue
                val expectedIns = incomingWords(method)
                if (expectedIns > implementation.registerCount) {
                    error("$label emitted invalid frame for " +
                            "${method.definingClass}->${method.name}(" +
                            method.parameters.joinToString("") { it.type } +
                            ")${method.returnType}: " +
                            "registers_size=${implementation.registerCount}, " +
                            "expected_ins_size=$expectedIns, " +
                            "access=0x${method.accessFlags.toString(16)}")
                }
            }
        }
    }

    fun rewrite(
        origDex: ByteArray,
        dex: DexParser,
        injectLoader: Boolean,
        /** Dex descriptor of the per-output loader class, e.g. "Lcom/qk3zr/xy;". */
        loaderClass: String,
        appClassName: String? = null,
        /** Dex descriptors to inject initVM into when the app declares no
         *  custom Application class. Activities and services are expected to be
         *  ContextWrapper subclasses; the superclass-chain guard remains a second
         *  safety net. */
        componentClassDescs: List<String> = emptyList(),
        /** loadLibrary() argument baked into the injected loader <clinit>. */
        libName: String = "VMP",
        /** Per-pack name for the renamed original attachBaseContext. */
        attachOrigName: String = "attachBaseContext_vmp_orig",
        debugMode: Boolean = false,
        onLog: (String) -> Unit
    ): ByteArray {
        val virtualizedKeys = dex.keysWithCode()
        onLog("DexParser found ${virtualizedKeys.size} methods with code")

        val opcodes = Opcodes.forApi(34)
        val dexPool = DexPool(opcodes)

        val origDexFile: DexFile = DexBackedDexFile(opcodes, origDex)
        val classSuperclasses = origDexFile.classes.associate { it.type to it.superclass }

        val initVMRef = ImmutableMethodReference(
            loaderClass, "initVM", listOf(ASSET_MANAGER_CLASS, "I", "Z", CONTEXT_CLASS), "V")

        var classCount = 0
        var methodCount = 0
        var nativeConverted = 0
        val virtualizedKeySet = HashSet<String>()
        var appInitPatched = false

        for (classDef in origDexFile.classes) {
            if (injectLoader && classDef.type == loaderClass)
                error("loader class $loaderClass collides with an app class in this dex")
            classCount++
            val isInterface = (classDef.accessFlags and AccessFlags.INTERFACE.value) != 0

            val methods = classDef.methods.map { method ->
                val hadCode = method.implementation != null
                val isConstructor = method.name == "<init>" || method.name == "<clinit>"
                val paramConcat = method.parameters.joinToString("") { it.type }
                val mKey =
                    "${method.definingClass}|${method.name}|$paramConcat|${method.returnType}"
                val insnCount = dex.insnsSizeOf(mKey)
                val frame = dex.frameOf(mKey)
                val virtualize = hadCode &&
                        (method.accessFlags and AccessFlags.NATIVE.value) == 0 &&
                        dex.policy.shouldVirtualize(
                    method.definingClass, method.name, paramConcat,
                    method.returnType,
                    isInterface, isConstructor,
                    instructionCount = insnCount,
                    registersSize = frame?.get(0) ?: 0,
                    insSize = frame?.get(1) ?: 0,
                    outsSize = frame?.get(2) ?: 0,
                    skips = dex.skips,
                    unsupportedOpcode = dex.unsupportedOpcodeOf(mKey),
                    isSynthetic = (method.accessFlags and 0x1000) != 0
                )

                val newAccess = if (virtualize) {
                    method.accessFlags or AccessFlags.NATIVE.value
                } else {
                    method.accessFlags
                }

                if (debugMode && method.name == "lambda\$onCreate\$0") {
                    val diagnosticParams = method.parameters.joinToString("") { it.type }
                    onLog("  frame diagnostic: " +
                            "${method.definingClass}->${method.name}($diagnosticParams)${method.returnType} " +
                            "hasCode=${method.implementation != null} " +
                            "sourceRegs=${method.implementation?.registerCount} " +
                            "access=0x${method.accessFlags.toString(16)} " +
                            "virtualize=$virtualize")
                }
                val originalImpl = method.implementation
                val newImpl: MethodImplementation? = if (virtualize) {
                    null
                } else {
                    originalImpl?.let {
                        val normalized = normalizeImplementation(method, it)
                        if (debugMode && (normalized.registerCount > it.registerCount ||
                                method.name == "lambda\$onCreate\$0")) {
                            onLog("  materialized register frame: " +
                                    "${method.definingClass}->${method.name} " +
                                    "${it.registerCount} -> ${normalized.registerCount}")
                        }
                        normalized
                    }
                }

                methodCount++
                if (virtualize) { nativeConverted++; virtualizedKeySet.add(mKey) }

                ImmutableMethod(
                    method.definingClass, method.name, method.parameters,
                    method.returnType, newAccess, method.annotations,
                    method.hiddenApiRestrictions, newImpl
                )
            }

            var finalMethods = methods
            if (appClassName != null && classDef.type == appClassName) {
                appInitPatched = true
                finalMethods = injectInitVmAttach(
                    classDef.type, classDef.superclass ?: SUPER_CLASS,
                    canInvokeAttachBaseContext(classDef.superclass, classSuperclasses),
                    methods, "App", attachOrigName, initVMRef, debugMode, onLog)
            } else if (classDef.type in componentClassDescs) {
                finalMethods = injectInitVmAttach(
                    classDef.type, classDef.superclass ?: SUPER_CLASS,
                    canInvokeAttachBaseContext(classDef.superclass, classSuperclasses),
                    methods, "Component", attachOrigName, initVMRef, debugMode, onLog)
            }
            if (debugMode) {
                finalMethods.filter { it.name == "lambda\$onCreate\$0" }.forEach { finalMethod ->
                    onLog("  final method: ${finalMethod.definingClass}->${finalMethod.name}(" +
                            finalMethod.parameters.joinToString("") { it.type } +
                            ")${finalMethod.returnType} access=0x${finalMethod.accessFlags.toString(16)} " +
                            "implRegs=${finalMethod.implementation?.registerCount}")
                }
            }
            val newClassDef = ImmutableClassDef(
                classDef.type, classDef.accessFlags, classDef.superclass,
                classDef.interfaces.map { it.toString() }, classDef.sourceFile,
                classDef.annotations, classDef.fields, finalMethods
            )
            dexPool.internClass(newClassDef)
        }

        val tableCount = dex.virtualizableKeys().size
        if (tableCount != virtualizedKeySet.size)
            error("virtualization set mismatch in this dex: ${virtualizedKeySet.size} " +
                    "distinct method keys made native, VMC code table expects $tableCount")

        onLog("Processed $classCount classes, $methodCount methods, " +
                "$nativeConverted made native")
        if (appClassName != null && !appInitPatched) {
            error("Application class $appClassName was not found in the selected dex; " +
                  "refusing to emit an APK without an initVM hook")
        }

        if (injectLoader) {
            injectLoaderClass(dexPool, debugMode, libName, loaderClass, initVMRef, onLog)
        }

        val dataStore = MemoryDataStore()
        try {
            dexPool.writeTo(dataStore)
        } catch (e: Throwable) {
            var root = e
            while (root.cause != null) root = root.cause!!
            onLog("DexWriter ROOT CAUSE: ${root.javaClass.name}: ${root.message}")
            onLog("DexWriter error: ${e.javaClass.name}: ${e.message}")
            onLog(e.stackTraceToString().take(4000))
            throw e
        }
        val result = DexPostProcessor.repairCodeItems(dataStore.data, onLog)
        onLog("Rewritten DEX size: ${result.size} bytes")
        return result
    }

    /**
     * Builds a fresh attachBaseContext(Context)V for an app class that does
     * not override it. initVM must run before the super call because the
     * original application/component lifecycle can invoke virtualized methods.
     * Frame: regs=5,
     * this=v3, context=v4, scratch v0 (assets) / v1 (dexIndex 0) / v2 (debug);
     * initVM's 4th argument (the pin's Context) reuses v4.
     */
    private fun buildAppAttachBaseContext(
        appClass: String,
        superClass: String,
        initVMRef: ImmutableMethodReference,
        debugMode: Boolean
    ): ImmutableMethod {
        val insns = listOf<Instruction>(
            BuilderInstruction11n(Opcode.CONST_4, 1, 0),
            BuilderInstruction11n(Opcode.CONST_4, 2, if (debugMode) 1 else 0),
            BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1,
                4, 0, 0, 0, 0, CTX_GET_ASSETS_REF),
            BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
            BuilderInstruction35c(Opcode.INVOKE_STATIC, initVMRef.parameterTypes.size,
                0, 1, 2, 4, 0, initVMRef),
            BuilderInstruction3rc(Opcode.INVOKE_SUPER_RANGE, 3, 2,
                ImmutableMethodReference(superClass, "attachBaseContext",
                    listOf(CONTEXT_CLASS), "V")),
            BuilderInstruction10x(Opcode.RETURN_VOID)
        )
        val impl = ImmutableMethodImplementation(5, insns,
            emptyList<com.android.tools.smali.dexlib2.iface.TryBlock<*>>(), null)
        return ImmutableMethod(appClass, "attachBaseContext",
            listOf(ImmutableMethodParameter(CONTEXT_CLASS, NO_ANNOTATIONS, null)), "V",
            AccessFlags.PROTECTED.value, NO_ANNOTATIONS, NO_HIDDEN_RESTRICTIONS, impl)
    }

    /**
     * Injects initVM via attachBaseContext: ADD a fresh method when absent, or
     * RENAME+WRAPPER around an existing one. The injected method is a real Java
     * body (never virtualized). The ADD path needs a superclass that declares
     * attachBaseContext (checked through the superclass chain); the RENAME+WRAPPER
     * path always calls the class's own renamed method, so it is always safe.
     */
    private fun injectInitVmAttach(
        classType: String,
        superClass: String,
        canInvokeSuperAttach: Boolean,
        methods: List<ImmutableMethod>,
        tag: String,
        attachOrigName: String,
        initVMRef: ImmutableMethodReference,
        debugMode: Boolean,
        onLog: (String) -> Unit
    ): List<ImmutableMethod> {
        val attach = methods.firstOrNull { m ->
            m.name == "attachBaseContext" && m.returnType == "V" &&
            m.parameters.size == 1 && m.parameters[0].type == CONTEXT_CLASS
        }
        return when {
            attach == null && !canInvokeSuperAttach -> {
                onLog("  WARNING: $tag $classType cannot be hooked (super " +
                      "$superClass declares no attachBaseContext); initVM NOT " +
                      "injected - an injected invokesuper there would fail " +
                      "verification with VerifyError")
                methods
            }
            attach == null -> {
                onLog("  $tag initVM: ADDED attachBaseContext to $classType")
                methods + buildAppAttachBaseContext(classType, superClass, initVMRef, debugMode)
            }
            attach.implementation != null &&
            (attach.accessFlags and (AccessFlags.NATIVE.value or AccessFlags.ABSTRACT.value)) == 0 -> {
                onLog("  $tag initVM: RENAME+WRAPPER around existing $classType.attachBaseContext")
                methods.map { m ->
                    if (m === attach)
                        ImmutableMethod(m.definingClass, attachOrigName,
                            m.parameters, m.returnType, m.accessFlags,
                            m.annotations, m.hiddenApiRestrictions, m.implementation)
                    else m
                } + buildAppAttachBaseContextWrapper(classType, attachOrigName, initVMRef, debugMode)
            }
            else -> {
                onLog("  WARNING: could not wrap $classType.attachBaseContext " +
                      "(native/abstract); initVM will NOT run from it")
                methods
            }
        }
    }

    /**
     * attachBaseContext wrapper for a class that already has one: initVM runs
     * first so the renamed lifecycle method cannot call an unregistered native
     * stub. The wrapper then delegates to the original method.
     * Frame: regs=5, this=v3, context=v4, scratch v0/v1/v2; v4 doubles as
     * initVM's Context (pin) argument.
     */
    private fun buildAppAttachBaseContextWrapper(
        appClassDesc: String,
        attachOrigName: String,
        initVMRef: ImmutableMethodReference,
        debugMode: Boolean
    ): ImmutableMethod {
        val insns = listOf<Instruction>(
            BuilderInstruction11n(Opcode.CONST_4, 1, 0),
            BuilderInstruction11n(Opcode.CONST_4, 2, if (debugMode) 1 else 0),
            BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1,
                4, 0, 0, 0, 0, CTX_GET_ASSETS_REF),
            BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
            BuilderInstruction35c(Opcode.INVOKE_STATIC, initVMRef.parameterTypes.size,
                0, 1, 2, 4, 0, initVMRef),
            BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2,
                3, 4, 0, 0, 0,
                ImmutableMethodReference(appClassDesc, attachOrigName,
                    listOf(CONTEXT_CLASS), "V")),
            BuilderInstruction10x(Opcode.RETURN_VOID)
        )
        val impl = ImmutableMethodImplementation(5, insns,
            emptyList<com.android.tools.smali.dexlib2.iface.TryBlock<*>>(), null)
        return ImmutableMethod(appClassDesc, "attachBaseContext",
            listOf(ImmutableMethodParameter(CONTEXT_CLASS, NO_ANNOTATIONS, null)), "V",
            AccessFlags.PROTECTED.value, NO_ANNOTATIONS, NO_HIDDEN_RESTRICTIONS, impl)
    }

    /** Build a loader-only dex without reserializing an existing application dex. */
    fun buildLoaderDex(
        loaderClass: String,
        applicationClass: String,
        libName: String,
        debugMode: Boolean,
        onLog: (String) -> Unit
    ): ByteArray {
        val opcodes = Opcodes.forApi(34)
        val dexPool = DexPool(opcodes)
        val initVMRef = ImmutableMethodReference(
            loaderClass, "initVM",
            listOf(ASSET_MANAGER_CLASS, "I", "Z", CONTEXT_CLASS), "V")
        injectLoaderClass(
            dexPool, debugMode, libName, loaderClass, initVMRef, onLog,
            superClass = applicationClass
        )
        val dataStore = MemoryDataStore()
        dexPool.writeTo(dataStore)
        return dataStore.data
    }

    private fun injectLoaderClass(
        dexPool: DexPool,
        debugMode: Boolean,
        libName: String,
        loaderClass: String,
        initVMRef: ImmutableMethodReference,
        onLog: (String) -> Unit,
        superClass: String = SUPER_CLASS
    ) {
        onLog("Injecting loader class $loaderClass")
        val emptyAnnotations = NO_ANNOTATIONS
        val noRestrictions = NO_HIDDEN_RESTRICTIONS

        val loadLibraryRef = ImmutableMethodReference("Ljava/lang/System;", "loadLibrary",
            listOf("Ljava/lang/String;"), "V")
        val appInitRef = ImmutableMethodReference(superClass, "<init>", emptyList(), "V")
        val appAttachRef = ImmutableMethodReference(superClass, "attachBaseContext",
            listOf(CONTEXT_CLASS), "V")
        val getAssetsRef = ImmutableMethodReference(CONTEXT_CLASS, "getAssets", emptyList(), ASSET_MANAGER_CLASS)

        val clinitImpl = MutableMethodImplementation(1)
        clinitImpl.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(libName)))
        clinitImpl.addInstruction(BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 0, 1, loadLibraryRef))
        clinitImpl.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val initImpl = MutableMethodImplementation(1)
        initImpl.addInstruction(BuilderInstruction3rc(Opcode.INVOKE_DIRECT_RANGE, 0, 1, appInitRef))
        initImpl.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val attachImpl = MutableMethodImplementation(5)
        attachImpl.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 1, 0))
        attachImpl.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 2, if (debugMode) 1 else 0))
        attachImpl.addInstruction(BuilderInstruction3rc(Opcode.INVOKE_VIRTUAL_RANGE, 4, 1, getAssetsRef))
        attachImpl.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
        attachImpl.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, initVMRef.parameterTypes.size, 0, 1, 2, 4, 0, initVMRef))
        attachImpl.addInstruction(BuilderInstruction3rc(Opcode.INVOKE_SUPER_RANGE, 3, 2, appAttachRef))
        attachImpl.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))

        val methods = listOf(
            ImmutableMethod(loaderClass, "<clinit>", emptyList(), "V",
                AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value,
                emptyAnnotations, noRestrictions, clinitImpl),
            ImmutableMethod(loaderClass, "<init>", emptyList(), "V",
                AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
                emptyAnnotations, noRestrictions, initImpl),
            ImmutableMethod(loaderClass, "initVM",
                listOf(ImmutableMethodParameter(ASSET_MANAGER_CLASS, emptyAnnotations, null),
                       ImmutableMethodParameter("I", emptyAnnotations, null),
                       ImmutableMethodParameter("Z", emptyAnnotations, null),
                       ImmutableMethodParameter(CONTEXT_CLASS, emptyAnnotations, null)),
                "V", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value or AccessFlags.NATIVE.value,
                emptyAnnotations, noRestrictions, null),
            ImmutableMethod(loaderClass, "attachBaseContext",
                listOf(ImmutableMethodParameter(CONTEXT_CLASS, emptyAnnotations, null)),
                "V", AccessFlags.PROTECTED.value, emptyAnnotations, noRestrictions, attachImpl)
        )

        val loaderDef = ImmutableClassDef(loaderClass, AccessFlags.PUBLIC.value, superClass,
            emptyList<String>(), null, emptyAnnotations, emptyList<com.android.tools.smali.dexlib2.iface.Field>(),
            methods)
        dexPool.internClass(loaderDef)
        onLog("Injected loader class $loaderClass with ${methods.size} methods")
    }
}
