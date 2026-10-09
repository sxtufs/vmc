package com.vmp.packer

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

/** Computes methods that may run before the first initVM hook and exempts them
 * from virtualization. It walks every class initializer, selected constructors,
 * and optionally all manifest components when no Application hook is available.
 * The walk is bounded; hitting a limit fails closed by broadening exemptions.
 * Keys use the policy form `Lcom/foo/Bar;->methodName`.
 */
object ClinitScan {

    private const val MAX_DEPTH = 12
    private const val MIN_VISITED = 20_000
    private const val MAX_VISITED = 200_000

    /** @return keys of the form "Lcom/foo/Bar;->methodName". */
    fun clinitExemptKeys(
        dexBytes: List<ByteArray>,
        earlyClassDescs: Set<String>,
        /** Prunes the walk: a callee outside the whitelist would stay native
         *  anyway, so exempting it would be noise. Pass the pre-clinit policy -
         *  its clinitExempt set is what this call computes. */
        policy: PackPolicy,
        onLog: (String) -> Unit
    ): Set<String> {
        val opcodes = Opcodes.forApi(34)
        val dexFiles = ArrayList<DexBackedDexFile>()
        for (bytes in dexBytes) {
            try {
                dexFiles.add(DexBackedDexFile(opcodes, bytes))
            } catch (t: Exception) {
                onLog("  PRE-VM SCAN: a dex file could not be parsed " +
                        "(${t.javaClass.simpleName}: ${t.message}) - skipped")
            }
        }
        if (dexFiles.isEmpty()) return emptySet()

        val index = HashMap<String, ClassDef>()
        for (dex in dexFiles) {
            for (cd in dex.classes) {
                if (!index.containsKey(cd.type)) index[cd.type] = cd
            }
        }

        val visitLimit = computeVisitBudget(index)
        onLog("  PRE-VM SCAN: traversal budget $visitLimit nodes")

        val exempt = HashSet<String>()
        val visited = HashSet<String>()
        val queue = ArrayDeque<Pair<String, Int>>()
        var initializers = 0
        var ctors = 0

        fun enqueue(key: String, depth: Int) {
            if (!visited.add(key)) return
            exempt.add(key)
            queue.addLast(key to depth)
        }

        fun seedFrom(cd: ClassDef, methodName: String, countAs: Int) {
            for (m in cd.methods) {
                if (m.name != methodName) continue
                val impl = m.implementation ?: continue
                if (countAs == 1) initializers++ else ctors++
                for (callee in invokesOf(impl.instructions)) enqueue(callee, 1)
            }
        }

        for (cd in index.values) seedFrom(cd, "<clinit>", 1)
        for (desc in earlyClassDescs) {
            val cd = index[desc] ?: continue
            seedFrom(cd, "<init>", 2)
        }

        var hitDepth = false
        var hitCap = false

        while (queue.isNotEmpty()) {
            if (visited.size >= visitLimit) {
                hitCap = true
                break
            }
            val item = queue.removeFirst()
            val key = item.first
            val depth = item.second
            val arrow = key.indexOf("->")
            if (arrow <= 0) continue
            val cls = key.substring(0, arrow)
            val name = key.substring(arrow + 2)
            if (!policy.isTargetAppClass(cls)) continue
            if (depth >= MAX_DEPTH) {
                hitDepth = true
                continue
            }
            val cd = index[cls] ?: continue
            for (m in cd.methods) {
                if (m.name != name) continue
                val impl = m.implementation ?: continue
                for (callee in invokesOf(impl.instructions)) {
                    enqueue(callee, depth + 1)
                }
            }
        }

        if (hitCap || hitDepth) {
            var failClosed = 0
            for (cd in index.values) {
                if (!policy.isTargetAppClass(cd.type)) continue
                for (m in cd.methods) {
                    if (m.implementation != null && exempt.add("${cd.type}->${m.name}"))
                        failClosed++
                }
            }
            onLog("  PRE-VM SCAN: fail-closed exemptions added: $failClosed method name(s)")
        }

        if (hitCap) {
            onLog("  PRE-VM SCAN: WARNING - stopped at $visitLimit nodes; some " +
                    "pre-initVM-reachable methods may still be virtualized")
        }
        if (hitDepth) {
            onLog("  PRE-VM SCAN: WARNING - depth cap $MAX_DEPTH reached")
        }

        onLog("  pre-initVM closure: $initializers <clinit> + $ctors <init> -> " +
                "${exempt.size} method key(s) exempt from virtualization")
        if (exempt.size > 2000) {
            onLog("  WARNING: the pre-initVM closure is large (${exempt.size} keys) - " +
                    "virtualization coverage will drop noticeably for this APK")
        }
        return exempt
    }

    private fun computeVisitBudget(index: Map<String, ClassDef>): Int {
        var codeMethods = 0L
        for (classDef in index.values) {
            for (method in classDef.methods) {
                if (method.implementation != null) codeMethods++
            }
        }
        return minOf(MAX_VISITED.toLong(), MIN_VISITED.toLong() + codeMethods / 4)
            .toInt()
    }

    /** Distinct "class->name" keys invoked by one instruction sequence. */
    private fun invokesOf(instructions: Iterable<Instruction>): List<String> {
        val out = ArrayList<String>(4)
        for (insn in instructions) {
            val holder = insn as? ReferenceInstruction ?: continue
            val ref = holder.reference as? MethodReference ?: continue
            out.add("${ref.definingClass}->${ref.name}")
        }
        return out
    }
}
