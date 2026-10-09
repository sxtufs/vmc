package com.vmp.packer

/**
 * Per-pack container decisions. Runtime capability negotiation is the only
 * external input; pruning and fusion policy are intentionally fixed for
 * reproducible production packs. Developer experiments belong in tests, not
 * mutable APK assets.
 */
class PackConfig(
    /** Highest VMP2 container version the embedded libVMP can parse. */
    val runtimeMaxContainerVersion: Int = 1
)
