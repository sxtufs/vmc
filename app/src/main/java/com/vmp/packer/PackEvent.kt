package com.vmp.packer

/** High-level phases exposed to the UI and exported logs. */
enum class PackPhase {
    PREFLIGHT, SCAN, PRE_VM, DEX, BUILD, SIGN, COMPLETE, CANCELLED
}

enum class PackSeverity { INFO, WARNING, ERROR }

data class PackEvent(
    val phase: PackPhase,
    val severity: PackSeverity = PackSeverity.INFO,
    val message: String,
    val current: Int? = null,
    val total: Int? = null,
    val plan: PackPlan? = null
) {
    val progress: Float?
        get() = if (current != null && total != null && total > 0) {
            current.toFloat() / total.toFloat()
        } else null
}
