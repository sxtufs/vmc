#ifndef VMP_IR_H
#define VMP_IR_H

#include <stdint.h>
#include <stddef.h>


/* Code-table access bit marking IR-encoded methods. Mirrors
 * IrCodec.IR_ACCESS_BIT; both sides must use the same value. DEX access flags
 * do not use bit 28, so the marker can share the access word. */
#define VMP_IR_ACCESS_BIT 0x10000000u

/* VMP2 header slots for the IR section descriptor. */
#define VMP_IR_OFF_SLOT  96
#define VMP_IR_SIZE_SLOT 100

/* Canonical markers for fused operations. These values mirror IrCodec and
 * interpreter.cpp. ART reserves 0xfa..0xff for invoke-polymorphic,
 * invoke-custom, and const-method instructions on supported versions. The
 * encoder rejects streams that could contain those opcodes, keeping the marker
 * range disjoint. Fusion changes only the first instruction's opcode; subsequent
 * instructions retain their addresses and normal handlers. */
#define VMP_FUSE_SETTER 0xfa  /* 22c: unit0 op|A<<8|B<<12, unit1 field */
#define VMP_FUSE_GETTER 0xfb  /* same operands */
#define VMP_FUSE_CONST  0xfc  /* 21c: unit0 op|A<<8, unit1 imm16 */
#define VMP_FUSE_CONSTW 0xfd  /* v2.1: const-wide/16, register pair */
#define VMP_FUSE_SETINV 0xfe  /* v2.1: iput + invoke + return-void */
#define VMP_FUSE_IF     0xff  /* v2.1: iget + if-eqz/if-nez */
/* Capability thresholds for the two marker generations. They mirror
 * IrCodec.IR_FUSE_CAP and IR_FUSE2_CAP. The packer selects patterns and the
 * container capability check gates them; the interpreter dispatches the marker
 * values directly. Keep these thresholds and literals synchronized with Kotlin. */
#define VMP_IR_FUSE_CAP 9
#define VMP_IR_FUSE2_CAP 10

/* Sum of widths[j]*2 - the original stream length in bytes. */
size_t vmpIrPlainLen(const uint16_t *widths, uint32_t count);

/* Re-expand the record region in place to the original unit stream. */
void vmpIrExpand(uint8_t *reg, const uint16_t *widths, uint32_t count);

#endif
