package com.vmp.packer

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.iface.reference.TypeReference

/**
 * Writes one little-endian VMP2 blob for a dex file. The 112-byte header stores
 * (size, offset) descriptors for strings, descriptors, string IDs, code, and
 * data; optional IR and permutation sections follow the data section. Version 1
 * uses dense string IDs, while version 2 uses sparse string IDs; feature bit 0
 * selects sparse descriptor tables.
 */
class VmcWriter(private val dex: DexParser, private val cfg: PackConfig) {

  private val runtimeMaxContainerVersion get() = cfg.runtimeMaxContainerVersion
  private val fuseDetail = false

  private val virtualizedKeys =
  dex.virtualizableKeys().sortedBy { dex.midxOf(it) }.filter { dex.midxOf(it) >= 0 }

  /** Per-output ISA permutation input: insn-start offsets (code units) per
   *  virtualized key, from InsnPerm.collectStarts; used only when cap >= 4 and the
   *  map covers every emitted record. Layout contract: InsnPerm.kt. */
  var insnStarts: Map<String, IntArray>? = null

  /** Fusion safety: branch/switch targets per key (InsnPerm.collectTargets);
   *  null = no fusion this dex. */
  var insnTargets: Map<String, IntArray>? = null

  /** Optional log sink for permutation decisions. */
  var onPermSkip: ((String) -> Unit)? = null

  /** Section byte counts from the last build(), for the pack log. */
  var lastBreakdown: String = ""
    private set

  /** Perm section: [lut 256 | u32 table offset per code record | tables] in
   *  code-table order, offsets relative to perm_off, store->canonical (the
   *  runtime applies it as-is, the packer inverts). See InsnPerm.kt. */
  private fun buildPermSection(keys: List<String>, starts: Map<String, IntArray>,
                               luts: List<ByteArray>?, sel: IntArray?): ByteArray {
    val multi = runtimeMaxContainerVersion >= InsnPerm.MULTI_PERM_CAP
    val nLut = if (multi) InsnPerm.PERM_LUT_COUNT else 1
    val selRnd = java.security.SecureRandom()
    val idxBase = nLut * InsnPerm.LUT_SIZE + (if (multi) keys.size else 0)
    var dataPos = idxBase + 4 * keys.size
    for (k in keys) dataPos += 2 + 2 * starts.getValue(k).size
    val buf = ByteBuffer.allocate(dataPos).order(ByteOrder.LITTLE_ENDIAN)
    for (l in 0 until nLut) buf.put(luts?.get(l) ?: InsnPerm.generateLut())
    if (multi)
      for (j in keys.indices)
        buf.put((sel?.get(j) ?: selRnd.nextInt(InsnPerm.PERM_LUT_COUNT)).toByte())
    var pos = idxBase + 4 * keys.size
    for (j in keys.indices) {
      buf.putInt(idxBase + 4 * j, pos)
      val st = starts.getValue(keys[j])
      buf.putShort(pos, st.size.toShort()); pos += 2
      for (s in st) { buf.putShort(pos, s.toShort()); pos += 2 }
    }
    return buf.array()
  }

  /** Header-only container for a dex that virtualizes nothing: open() derives
   *  methods_count = code_size/36 = 0, so every accessor bounds-checks to null. */
  private fun emptyContainer(): ByteArray {
    val buf = ByteBuffer.allocate(112)
    buf.order(ByteOrder.LITTLE_ENDIAN)
    buf.put("VMP2".toByteArray(Charsets.US_ASCII))
    buf.putInt(1)
    buf.putInt(112)
    buf.putInt(112)
    buf.putInt(0x12345678)
    lastBreakdown = "EMPTY (header only, 112 bytes)"
    missedStrings = emptyList()
    return buf.array()
  }

  private val strings = HashSet<String>()
  private val stringOffsets = HashMap<String, Int>()

  /** Table builders resolve a string by VALUE to a blob offset; a miss becomes
   *  offset 0. With pruning off that is the FIRST string in the sorted blob - a
   *  plausible wrong value - so misses are recorded for the pack log. */
  private val missed = ArrayList<String>()

  /** Strings that fell back to offset 0 during the last build(). */
  var missedStrings: List<String> = emptyList()
    private set

  /** Set by build() before collectStrings(): the keep set. null = no pruning,
   *  i.e. the whole dex string table is copied. */
  private var reachable: Set<String>? = null

  /** Table entries deliberately pointed at the empty-string sentinel. */
  private var prunedRefs = 0

  /** Why pruning did not happen in the last build() (null when it did), so the
   *  log can tell the kill switch from a swallowed walk failure. */
  var pruneSkipReason: String? = null
    private set

  /** Keys the walk could not correlate with DexParser's format: their bytecode
   *  still ships, so pruning was abandoned for this dex. */
  var unmatchedKeys: List<String> = emptyList()
    private set

  companion object {

    /** Feature bits live in header slot 20 rather than the blob version; the
     *  version field is updated later when ApkBuilder encrypts instructions. */
    const val FEATURE_SPARSE_DESCRIPTORS = 1

    /** Lowest vmp.abi.N token whose runtime can read FEATURE_SPARSE_DESCRIPTORS. */
    const val SPARSE_DESCRIPTORS_CAP = 5
  }

  private var sparseDesc = false

  private fun offsetOf(s: String?): Int {
    if (s == null) {
      if (reachable == null) missed.add("<null>") else prunedRefs++
      return 0
    }
    val v = stringOffsets[s]
    if (v == null) {
      if (reachable == null) missed.add(s) else prunedRefs++
      return 0
    }
    return v
  }

  /** Builds the VMP2 container and patches file_size (offset 8). */
  fun build(): ByteArray {
    strings.clear()
    stringOffsets.clear()
    missed.clear()
    prunedRefs = 0
    unmatchedKeys = emptyList()
    reachable = null
    sparseDesc = false
    if (virtualizedKeys.isEmpty()) return emptyContainer()

    pruneSkipReason = null
    reachable = computeReachable()
    sparseDesc = reachable != null && runtimeMaxContainerVersion >= SPARSE_DESCRIPTORS_CAP

    collectStrings()

    val stringData = buildStringData()

    val keep = reachable
    val sparseStrIds = keep != null && runtimeMaxContainerVersion >= 2
    val stringIdTable: ByteBuffer
    if (sparseStrIds) {
      val pairs = ArrayList<IntArray>()
      for (i in 0 until dex.stringCount()) {
        val s = dex.stringByIdx(i)
        if (s in keep) {
          val o = stringOffsets[s]
          if (o != null && (o != 0 || s.isEmpty())) pairs.add(intArrayOf(i, o))
        }
      }
      stringIdTable = ByteBuffer.allocate(4 + pairs.size * 8)
      stringIdTable.order(ByteOrder.LITTLE_ENDIAN)
      stringIdTable.putInt(pairs.size)
      for (p in pairs) { stringIdTable.putInt(p[0]); stringIdTable.putInt(p[1]) }
    } else {
      stringIdTable = ByteBuffer.allocate(dex.stringCount() * 4)
      stringIdTable.order(ByteOrder.LITTLE_ENDIAN)
      for (i in 0 until dex.stringCount()) {
        stringIdTable.putInt(offsetOf(dex.stringByIdx(i)))
      }
    }

    val rch = reachable
    val tables = VmcTables(dex, sparseDesc, ::offsetOf)
    val typeTable = tables.buildTypeTable(rch)
    val protoTable = tables.buildProtoTable(rch)
    val fieldTable = tables.buildFieldTable(rch)
    val methodTable = tables.buildMethodTable(rch)

    val vkeys = virtualizedKeys.toList()
    val codeView = HashMap<String, DexCode?>(vkeys.size * 2)
    for (key in vkeys) if (!codeView.containsKey(key)) codeView[key] = dex.codeOf(key)

    val permWalkOk = run {
      val st0 = insnStarts ?: return@run false
      for (key in vkeys) {
        val st = st0[key] ?: return@run false
        val code = codeView[key] ?: return@run false
        if (st.isEmpty() || st[0] != 0 || st.last() >= code.insnsSize) return@run false
        for (i in 1 until st.size) if (st[i] <= st[i - 1]) return@run false
      }
      true
    }
    val protectable = sparseStrIds
    val permEligible = protectable && permWalkOk &&
            runtimeMaxContainerVersion >= 4
    val irEligible = protectable && permWalkOk &&
            runtimeMaxContainerVersion >= IrCodec.IR_MIN_CAP &&
            runtimeMaxContainerVersion >= InsnPerm.MULTI_PERM_CAP
    if (!protectable && runtimeMaxContainerVersion >= 3)
      onPermSkip?.invoke("NOTE: dense string-id container (metadata pruning off or " +
              "the reachability walk declined) - per-method insn encryption and ISA " +
              "permutation are NOT emitted: bumping the blob version would misdescribe " +
              "its string-id table. The container stays canonical v1.")

    val irEnc = HashMap<String, IrCodec.Encoded>()
    var irLuts: List<ByteArray>? = null
    var irSel: IntArray? = null
    var irFused = 0
    var irMask = 0
    val fuseLog = ArrayList<String>()
    run {
      val st0 = insnStarts
      if (st0 != null && runtimeMaxContainerVersion >= IrCodec.IR_MIN_CAP) {
        val permWillEmit = irEligible
        if (permWillEmit) {
          irLuts = List(InsnPerm.PERM_LUT_COUNT) { InsnPerm.generateLut() }
          val rnd = java.security.SecureRandom()
          irSel = IntArray(vkeys.size) { rnd.nextInt(InsnPerm.PERM_LUT_COUNT) }
          val fuseOn = runtimeMaxContainerVersion >= IrCodec.IR_FUSE_CAP &&
                  insnTargets != null
          val draw = rnd.nextInt(IrCodec.P_ALL + 1)
          irMask = if (runtimeMaxContainerVersion >= IrCodec.IR_FUSE2_CAP) draw
                   else draw and IrCodec.P_V20
          var rec = 0
          for (key in vkeys) {
            val st = st0[key]
            val code = if (st != null) codeView[key] else null
            if (st != null && code != null) {
              val tg = if (fuseOn && code.flatTriesCount == 0)
                  insnTargets!![key] else null
              val enc = IrCodec.encode(code.insns, st, code.insnsSize,
                      irLuts!![irSel!![rec]], tg, irMask) { s, mk, o0, o1 ->
                  if (fuseLog.size < 16)
                      fuseLog.add("$key @u$s: 0x" + o0.toString(16) + "+0x" +
                              o1.toString(16) + " ->0x" + mk.toString(16))
              }
              if (enc != null) { irEnc[key] = enc; irFused += enc.fused }
            }
            if (code != null) rec++
          }
        }
      }
    }

    if (irEnc.isNotEmpty()) {
      var irDropped = 0
      val itr = irEnc.entries.iterator()
      while (itr.hasNext()) {
        val e = itr.next()
        val c = codeView[e.key]
        if (c == null || c.insnsSize != e.value.widths.sum()) {
          itr.remove(); irDropped++
        }
      }
      if (irDropped > 0)
        onPermSkip?.invoke("IR: $irDropped key(s) dropped to canonical " +
                "(insnsSize view mismatch vs code table)")
    }
    if (irFused > 0) {
      onPermSkip?.invoke("IR v2.1: mask=0x" + irMask.toString(16) + ", " +
              "$irFused patterns fused across ${irEnc.size} IR methods")
      if (fuseDetail && fuseLog.isNotEmpty())
        onPermSkip?.invoke("  fuse detail: " + fuseLog.joinToString("; "))
    }

    val insnData = ByteArrayOutputStream()
    val tryData = ByteArrayOutputStream()
    val insnOffsets = HashMap<String, Int>()
    val tryOffsets = HashMap<String, Int>()

    for (key in vkeys) {
      val code = codeView[key]
          ?: error("missing code item for virtualized method $key")
      insnOffsets[key] = insnData.size()
      val ir = irEnc[key]
      if (ir != null) insnData.write(ir.records)
      else insnData.write(code.insns)
      while (insnData.size() % 4 != 0) insnData.write(0)
    }
    for (key in vkeys) {
      val code = codeView[key]
          ?: error("missing code item for virtualized method $key")
      if (code.flatTriesCount > 0) {
        tryOffsets[key] = insnData.size() + tryData.size()
        tryData.write(code.flatTries)
        while (tryData.size() % 4 != 0) tryData.write(0)
      }
    }

    val combinedData = ByteArray(insnData.size() + tryData.size())
    System.arraycopy(insnData.toByteArray(), 0, combinedData, 0, insnData.size())
    System.arraycopy(tryData.toByteArray(), 0, combinedData, insnData.size(), tryData.size())

    val codeTable = ByteBuffer.allocate(virtualizedKeys.size * 36)
    codeTable.order(ByteOrder.LITTLE_ENDIAN)
    for (key in vkeys) {
      val code = codeView[key]
          ?: error("missing code item for virtualized method $key")
      if (code.ins > code.regs || code.insnsSize < 0)
        error("frame veto bypassed for $key: regs=${code.regs} ins=${code.ins} " +
                "outs=${code.outs} insnsSize=${code.insnsSize}")
      codeTable.putInt(dex.midxOf(key))
      codeTable.putInt(dex.accessOf(key) or
              if (irEnc.containsKey(key)) IrCodec.IR_ACCESS_BIT else 0)
      codeTable.putInt(code.regs)
      codeTable.putInt(code.ins)
      codeTable.putInt(code.outs)
      codeTable.putInt(code.insnsSize)
      codeTable.putInt(insnOffsets[key] ?: 0)
      codeTable.putInt(code.flatTriesCount)
      codeTable.putInt(tryOffsets[key] ?: 0)
    }

    val headerSize = 112
    var dataOffset = headerSize

    val stringsOff = dataOffset
    val stringsSize = stringData.size
    dataOffset += stringsSize

    val typesOff = dataOffset
    val typesSize = typeTable.size
    dataOffset += typesSize

    val protosOff = dataOffset
    val protosSize = protoTable.size
    dataOffset += protosSize

    val fieldsOff = dataOffset
    val fieldsSize = fieldTable.size
    dataOffset += fieldsSize

    val methodsOff = dataOffset
    val methodsSize = methodTable.size
    dataOffset += methodsSize

    val stringIdsOff = dataOffset
    val stringIdsSize = stringIdTable.capacity()
    dataOffset += stringIdsSize

    val codeOff = dataOffset
    val codeSize = codeTable.capacity()
    dataOffset += codeSize

    val dataSectionOff = dataOffset
    val dataSectionSize = combinedData.size
    dataOffset += dataSectionSize

    var irSection: ByteArray? = null
    var irOff = 0
    if (irEnc.isNotEmpty()) {
      val n = virtualizedKeys.size
      val irTables = ArrayList<ByteArray>()
      val irIdx = IntArray(n)
      var tabPos = 8 + 4 * n
      var rec = 0
      for (key in vkeys) {
        if (codeView[key] == null) continue
        val enc = irEnc[key]
        if (enc != null) {
          val t = ByteBuffer.allocate(2 + 2 * enc.widths.size + 32)
            .order(ByteOrder.LITTLE_ENDIAN)
          t.putShort(enc.widths.size.toShort())
          for (w in enc.widths) t.putShort(w.toShort())
          t.put(enc.sha256)
          irIdx[rec] = tabPos; tabPos += t.capacity()
          irTables.add(t.array())
        }
        rec++
      }
      val ib = ByteBuffer.allocate(tabPos).order(ByteOrder.LITTLE_ENDIAN)
      ib.putInt(n)
      for (j in 0 until n) ib.putInt(4 + 4 * j, irIdx[j])
      ib.putInt(4 + 4 * n, irFused)
      var tp = 8 + 4 * n
      for (t in irTables) { ib.position(tp); ib.put(t); tp += t.size }
      irSection = ib.array()
      irOff = dataOffset
      dataOffset += irSection.size
    }

    var permSection: ByteArray? = null
    var permOff = 0
    val starts = insnStarts
    if (starts != null && permEligible) {
      permSection = buildPermSection(vkeys, starts, irLuts, irSel)
      permOff = dataOffset
    } else if (starts != null && protectable &&
            runtimeMaxContainerVersion >= 4) {
      onPermSkip?.invoke("perm walk incomplete for this dex - shipping canonical")
    }
    val fileSize = dataOffset + (permSection?.size ?: 0)

    val buf = ByteBuffer.allocate(fileSize)
    buf.order(ByteOrder.LITTLE_ENDIAN)

    buf.put("VMP2".toByteArray(Charsets.US_ASCII))
    buf.putInt(if (sparseStrIds) 2 else 1)
    buf.putInt(0)
    buf.putInt(112)
    buf.putInt(0x12345678)
    buf.putInt(if (sparseDesc) FEATURE_SPARSE_DESCRIPTORS else 0)
    buf.putInt(0)

    buf.putInt(stringsSize); buf.putInt(stringsOff)
    buf.putInt(typesSize); buf.putInt(typesOff)
    buf.putInt(protosSize); buf.putInt(protosOff)
    buf.putInt(fieldsSize); buf.putInt(fieldsOff)
    buf.putInt(methodsSize); buf.putInt(methodsOff)
    buf.putInt(codeSize); buf.putInt(codeOff)
    buf.putInt(dataSectionSize); buf.putInt(dataSectionOff)

    buf.putInt(stringIdsSize); buf.putInt(stringIdsOff)

    while (buf.position() < headerSize) buf.put(0.toByte())

    buf.putInt(92, permOff)
    buf.putInt(96, irOff)
    buf.putInt(100, irSection?.size ?: 0)

    buf.put(stringData)
    buf.put(typeTable)
    buf.put(protoTable)
    buf.put(fieldTable)
    buf.put(methodTable)
    buf.put(stringIdTable.array())
    buf.put(codeTable.array())
    buf.put(combinedData)
    irSection?.let { buf.put(it) }
    permSection?.let { buf.put(it) }

    buf.putInt(8, fileSize)

    val codeBytes = codeSize + dataSectionSize
    val meta = fileSize - codeBytes
    lastBreakdown = "code=$codeBytes metadata=$meta (" +
            "${if (fileSize > 0) meta * 100 / fileSize else 0}%) " +
            "[str=$stringsSize types=$typesSize protos=$protosSize " +
            "fields=$fieldsSize methods=$methodsSize strIds=$stringIdsSize]" +
            (if (reachable != null)
                " [pruned: ${strings.size}/${dex.stringCount()} strings kept, " +
                "$prunedRefs refs -> sentinel" +
                (if (sparseStrIds) "" else ", strIds DENSE - stale libVMP") +
                (if (sparseDesc) ", desc SPARSE" else ", desc DENSE - stale libVMP") + "]"
            else
                " [prune OFF: ${pruneSkipReason ?: "reason unknown"}]")

    missedStrings = missed.distinct()

    return buf.array()
  }

  /**
   * Which DEX strings the interpreter can ever be ASKED for.
   *
   * The descriptor tables stay index-addressed (bytecode carries raw dex indices),
   * but the string BLOB need not: an unreferenced entry is never read, so it can
   * point at the sentinel and the blob scales with reachability.
   *
   * Collected by VALUE with dexlib2, which can only over-include (shared names
   * waste bytes), never under-include. null = pruning off; any exception falls back
   * to the full table, so a walk gap costs size, never correctness.
   */
  private fun computeReachable(): Set<String>? = try {
    val keep = HashSet<String>()
    val dexFile = DexBackedDexFile(Opcodes.forApi(34), dex.rawBytes())
    val vset = virtualizedKeys.toHashSet()
    val matched = HashSet<String>()

    for (classDef in dexFile.classes) {
      for (method in classDef.methods) {
        val impl = method.implementation ?: continue
        val key = "${method.definingClass}|${method.name}|" +
                method.parameters.joinToString("") { it.type } + "|" +
                method.returnType
        if (key !in vset) continue
        matched.add(key)

        keep.add(method.name)
        keep.add(method.definingClass)
        keep.add(method.returnType)
        method.parameters.forEach { keep.add(it.type) }

        for (ins in impl.instructions) {
          if (ins !is ReferenceInstruction) continue
          when (val r = ins.reference) {
            is StringReference -> keep.add(r.string)
            is TypeReference -> keep.add(r.type)
            is MethodReference -> {
              keep.add(r.name)
              keep.add(r.definingClass)
              keep.add(r.returnType)
              r.parameterTypes.forEach { keep.add(it.toString()) }
            }
            is FieldReference -> {
              keep.add(r.name)
              keep.add(r.definingClass)
              keep.add(r.type)
            }
            else -> throw IllegalStateException(
                    "unhandled reference type: ${r.javaClass.name}")
          }
        }

        for (tb in impl.tryBlocks) {
          for (eh in tb.exceptionHandlers) {
            eh.exceptionType?.let { keep.add(it) }
          }
        }
      }
    }

    for (i in 0 until dex.methodCount()) {
      val off = dex.methodIdOffset(i)
      if (dex.stringByIdx(dex.u4(off + 4)) !in keep) continue
      if (dex.typeDesc(dex.u2(off)) !in keep) continue
      val proto = dex.u2(off + 2)
      keep.add(dex.protoShortyByIdx(proto))
      keep.add(dex.jniSig(proto))
      dex.protoParams(proto).forEach { keep.add(it) }
    }
    for (i in 0 until dex.fieldCount()) {
      val off = dex.fieldIdOffset(i)
      if (dex.stringByIdx(dex.u4(off + 4)) !in keep) continue
      if (dex.typeDesc(dex.u2(off)) !in keep) continue
      keep.add(dex.typeDesc(dex.u2(off + 2)))
    }

    if (matched.size != vset.size) {
      unmatchedKeys = (vset - matched).toList().sorted()
      throw IllegalStateException(
              "key correlation: walk matched ${matched.size} of ${vset.size} " +
              "virtualized methods; first unmatched: ${unmatchedKeys.firstOrNull()}")
    }

    keep
  } catch (t: Exception) {
    pruneSkipReason = "${t.javaClass.simpleName}: ${t.message}"
    null
  }

  private fun collectStrings() {
    val keep = reachable
    if (keep == null) {
      for (i in 0 until dex.stringCount()) strings.add(dex.stringByIdx(i))
      for (i in 0 until dex.typeCount()) strings.add(dex.typeDesc(i))
      for (i in 0 until dex.methodCount()) {
        strings.add(dex.stringByIdx(dex.u4(dex.methodIdOffset(i) + 4)))
      }
      for (i in 0 until dex.fieldCount()) {
        strings.add(dex.stringByIdx(dex.u4(dex.fieldIdOffset(i) + 4)))
      }
      for (i in 0 until dex.protoCount()) {
        strings.add(dex.protoShortyByIdx(i))
        strings.add(dex.jniSig(i))
      }
      return
    }
    for (i in 0 until dex.stringCount()) {
      val s = dex.stringByIdx(i); if (s in keep) strings.add(s)
    }
    for (i in 0 until dex.typeCount()) {
      val s = dex.typeDesc(i); if (s in keep) strings.add(s)
    }
    for (i in 0 until dex.methodCount()) {
      val s = dex.stringByIdx(dex.u4(dex.methodIdOffset(i) + 4))
      if (s in keep) strings.add(s)
    }
    for (i in 0 until dex.fieldCount()) {
      val s = dex.stringByIdx(dex.u4(dex.fieldIdOffset(i) + 4))
      if (s in keep) strings.add(s)
    }
    for (i in 0 until dex.protoCount()) {
      val sh = dex.protoShortyByIdx(i); if (sh in keep) strings.add(sh)
      val sg = dex.jniSig(i); if (sg in keep) strings.add(sg)
      dex.protoParams(i).forEach { if (it in keep) strings.add(it) }
    }
  }

  private fun buildStringData(): ByteArray {
    val baos = ByteArrayOutputStream()
    baos.write(0)
    for (s in strings.sorted()) {
      if (s.isEmpty()) { stringOffsets[s] = 0; continue }
      stringOffsets[s] = baos.size()
      baos.write(encodeMutf8(s))
      baos.write(0)
    }
    return baos.toByteArray()
  }

  /** Encodes a string as JNI Modified UTF-8 (U+0000 as 0xC0 0x80).
   * Supplementary characters remain as their two UTF-16 surrogate code units;
   * JNI's NewStringUTF does not consume standard four-byte UTF-8 here. */
  private fun encodeMutf8(s: String): ByteArray {
    val baos = ByteArrayOutputStream()
    for (c in s) {
      val cp = c.code
      when {
        cp == 0 -> {
          baos.write(0xc0)
          baos.write(0x80)
        }
        cp < 0x80 -> baos.write(cp)
        cp < 0x800 -> {
          baos.write(0xc0 or (cp shr 6))
          baos.write(0x80 or (cp and 0x3f))
        }
        else -> {
          baos.write(0xe0 or (cp shr 12))
          baos.write(0x80 or ((cp shr 6) and 0x3f))
          baos.write(0x80 or (cp and 0x3f))
        }
      }
    }
    return baos.toByteArray()
  }

  /** Exposed only to the pure-JVM format harness. */
  internal fun encodeMutf8ForTest(s: String): ByteArray = encodeMutf8(s)

}

/** Empty VMP2 container used for dexes that carry no virtualized methods. */
internal fun emptyVmcContainer(): ByteArray {
  return ByteBuffer.allocate(112).order(ByteOrder.LITTLE_ENDIAN).apply {
    put("VMP2".toByteArray(Charsets.US_ASCII))
    putInt(1)
    putInt(112)
    putInt(112)
    putInt(0x12345678)
  }.array()
}
