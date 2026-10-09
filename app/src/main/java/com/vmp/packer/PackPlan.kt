package com.vmp.packer

/** Coverage and decisions produced by one pack run. */
data class DexPlan(
    val name: String,
    val inputBytes: Int,
    val candidateMethods: Int,
    val virtualizedMethods: Int,
    val vmcBytes: Int,
    val rewritten: Boolean,
    val skipReason: String? = null
)

data class PackPlan(
    val abis: List<String>,
    val loaderDex: String?,
    val standaloneLoader: Boolean,
    val componentHooks: List<String>,
    val skippedComponents: List<String>,
    val dexes: List<DexPlan>,
    val totalCandidates: Int,
    val totalVirtualized: Int,
    val totalVmcBytes: Int
)
