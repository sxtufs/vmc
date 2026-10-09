package com.vmp.packer

import com.android.tools.smali.dexlib2.iface.instruction.Instruction

/**
 * Opcode families that the native interpreter deliberately does not execute.
 *
 * Classification of the current exclusions:
 *
 *  - INVOKE_POLYMORPHIC*, INVOKE_CUSTOM*, CONST_METHOD_* are
 *    INTENTIONAL / REQUIRED and INTENTIONAL / ARCHITECTURAL. Their DEX IDs
 *    0xfa..0xff are reused by VMP fused markers (IrCodec and interpreter.cpp).
 *    A method containing one of these instructions must remain an ordinary
 *    ART/Dalvik method; putting it in VMC would make the real instruction
 *    collide with a fused operation.
 *
 * This list is deliberately limited to the six collision families. It is not a
 * temporary workaround for ordinary arithmetic/conversion opcodes. Keep the
 * list shared by DexParser selection and DexRewriter stub generation so both
 * passes make the same method-level decision.
 */
object InterpreterOpcodePolicy {
    private val UNSUPPORTED = setOf(
        "INVOKE_POLYMORPHIC",
        "INVOKE_POLYMORPHIC_RANGE",
        "INVOKE_CUSTOM",
        "INVOKE_CUSTOM_RANGE",
        "CONST_METHOD_HANDLE",
        "CONST_METHOD_TYPE"
    )

    internal fun isUnsupportedOpcodeName(name: String): Boolean = name in UNSUPPORTED

    fun firstUnsupported(instructions: Iterable<Instruction>): String? =
        instructions.firstOrNull { isUnsupportedOpcodeName(it.opcode.name) }?.opcode?.name
}
