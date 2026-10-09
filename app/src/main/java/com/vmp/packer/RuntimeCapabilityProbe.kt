package com.vmp.packer

/**
 * What the embedded libVMP binaries say they can parse, and therefore what this
 * pack may emit. Computed from the bytes about to be embedded, because a constant
 * cannot catch a stale .so or a sparse table that would otherwise be misread silently.
 * The probe is JVM-pure so it can run without Android dependencies.
 */
object RuntimeCapabilityProbe {

    /**
     * @param cap     ceiling: the lowest vmp.abi.N among the binaries, or 1
     *                (dense, which nothing can misread) if any ABI did not answer.
     * @param noToken ABIs that did not answer: no build, asset absent, unreadable,
     *                or a template predating the token.
     * @param minCap  floor among ABIs that returned a capability - the only one allowed to
     *                refuse the pack. Unsupported ABIs do not lower this value;
     *                they are handled by the uncovered-ABI check.
     */
    class Result(val cap: Int, val noToken: List<String>, val minCap: Int)

    /** The vmp.abi.N literal in a .so image, or null. Read as ISO-8859-1 so no
     *  byte can make the token unfindable. */
    fun tokenOf(soBytes: ByteArray): Int? =
        Regex("vmp\\.abi\\.(\\d+)")
            .find(String(soBytes, Charsets.ISO_8859_1))
            ?.groupValues?.get(1)?.toIntOrNull()

    /**
     * @param abiBytes abi -> the exact bytes that will be embedded, or null when
     *                 this packer has no readable libVMP for that ABI.
     */
    fun probe(abiBytes: Map<String, ByteArray?>): Result {
        val caps = abiBytes.mapValues { (_, b) -> b?.let { tokenOf(it) } }
        val noToken = caps.filterValues { it == null }.keys.toList()
        val cap = if (noToken.isNotEmpty()) 1
                  else caps.values.filterNotNull().minOrNull() ?: 1
        val minCap = abiBytes.filterValues { it != null }.keys
            .mapNotNull { caps[it] }.minOrNull() ?: 1
        return Result(cap, noToken, minCap)
    }

    /** Refuse at pack time rather than ship an APK whose VM dies on the first
     *  virtualized method: an older template cannot parse what this packer emits. */
    fun requireFloor(r: Result) {
        if (r.minCap < InsnPerm.MULTI_PERM_CAP)
            error("libVMP templates predate the current container contract " +
                    "(need vmp.abi.${InsnPerm.MULTI_PERM_CAP}: cert-bound keys " +
                    "+ multi-LUT perm, found v${r.minCap}) - rebuild native " +
                    "artifacts for every supported ABI")
    }

    /** Formats the pack-log capability verdict, including checked ABIs. */
    fun verdict(r: Result, checked: Collection<String>): String = when {
        r.cap >= 2 && r.noToken.isEmpty() ->
            "  libVMP capability: v${r.cap} -> sparse " +
                    (if (r.cap >= VmcWriter.SPARSE_DESCRIPTORS_CAP)
                        "string-id + descriptor tables"
                    else "string-id table") +
                    (if (r.cap >= InsnPerm.MULTI_PERM_CAP)
                        " + multi-LUT ISA perm" else "") +
                    (if (r.cap >= IrCodec.IR_MIN_CAP)
                        " + IR record containers" else "") +
                    (if (r.cap >= IrCodec.IR_FUSE_CAP)
                        " + v2 fused ops" else "") +
                    (if (r.cap >= IrCodec.IR_FUSE2_CAP)
                        " + v2.1 patterns" else "") +
                    " available [checked: ${checked.joinToString()}]"
        r.noToken.isNotEmpty() ->
            "  libVMP capability: UNRECOGNISED libVMP, no vmp.abi.N token in " +
                    "${r.noToken.joinToString()} -> assuming v1, dense. Rebuild " +
                    "those .so files. [checked: ${checked.joinToString()}]"
        else -> "  libVMP capability: reads container v1 only -> DENSE " +
                "string-id table (blob prune still applies). Rebuild the .so " +
                "for the sparse table. [checked: ${checked.joinToString()}]"
    }
}
