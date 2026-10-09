package com.vmp.packer

import java.security.SecureRandom

/**
 * The per-pack names, drawn together. ApkBuilder patches these literals into the
 * embedded .so, DexRewriter injects the loader class into the dex, and the dex's
 * System.loadLibrary() names the lib - so they are drawn as one object and no
 * call site can pair one pack's lib name with another's loader.
 *
 * Each width is an in-place patch slot, so it is asserted rather than merely
 * documented: a longer name overwrites the neighbouring literal and nothing at
 * runtime notices.
 */
object PackIdentity {

    class Identity(
        /** 3 chars: "lib" + name + ".so" must equal "libVMP.so" (9) so the packer
         *  can rewrite the ELF SONAME in place (ApkBuilder.patchSoname). */
        val libName: String,
        /** The original attachBaseContext is renamed to this in the hooked class
         *  so the injected override can call through. */
        val attachOrigName: String,
        /** Max 10 chars: the patched .so literal slot is 11 chars + NUL. */
        val containerAsset: String,
        /** "com/<5>/<2>" - exactly 12 bytes, the size of the kLoaderClass .rodata
         *  literal ApkBuilder rewrites in the embedded .so. Bound via
         *  RegisterNatives from JNI_OnLoad, NOT by Java_<class>_<method> export
         *  lookup: .dynstr hash tables go stale on an in-place rename. */
        val loaderClassSlash: String
    ) {
        /** Descriptor form - what the dex and DexRewriter match on. */
        val loaderClassDesc: String get() = "L$loaderClassSlash;"
    }

    fun draw(): Identity {
        val libName = "g" + randomTag(2)
        val containerAsset = "vm" + randomTag(8)
        val loaderClassSlash =
                "com/${letterTag() + randomTag(4)}/${letterTag() + randomTag(1)}"
        val id = Identity(libName, "attachBaseContext_" + randomTag(6),
                containerAsset, loaderClassSlash)
        if (id.libName.length != 3)
            error("libName '${id.libName}' is not 3 chars: lib$libName.so must " +
                    "occupy exactly the 9-byte libVMP.so SONAME slot")
        if (id.containerAsset.length > 10)
            error("assets/${id.containerAsset} exceeds the 10-char container-name " +
                    "literal slot in the embedded .so")
        if (id.loaderClassSlash.length != 12)
            error("loader class '${id.loaderClassSlash}' is not 12 bytes: the " +
                    "kLoaderClass .rodata slot is exactly 12")
        return id
    }

    /** One random [a-z] letter: identifier segments must not start with a digit. */
    private fun letterTag(): Char {
        val letters = "abcdefghijklmnopqrstuvwxyz"
        return letters[SecureRandom().nextInt(letters.length)]
    }

    /** Lowercase [a-z0-9] tag from a fresh SecureRandom. */
    private fun randomTag(len: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        val rnd = SecureRandom()
        return buildString(len) {
            repeat(len) { append(alphabet[rnd.nextInt(alphabet.length)]) }
        }
    }
}
