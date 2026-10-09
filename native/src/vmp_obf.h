#ifndef VMP_OBF_H
#define VMP_OBF_H

#include <stdint.h>

/*
 * Mixed boolean-arithmetic (MBA) + opaque predicates for the cold security path
 * (JNI_OnLoad key-slot decrypt, vmpChaChaTransform). ALGEBRAICALLY EQUAL to the
 * plain operators, so the RFC 8439 KAT still passes and the container bytes are
 * unchanged; they only make static reading of the decode path more expensive.
 *
 * Deliberately NOT applied to the ChaCha20 round function, which must stay
 * bit-exact against the RFC vector.
 */

/* a ^ b, computed without a literal '^': (a|b) minus the shared bits. */
static inline uint32_t vmp_xor(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}

/*
 * Obfuscation predicate whose result is always harmless: call sites only guard
 * no-ops (e.g. `key ^= 0`), so it can never change the computed bytes. The
 * volatile seed keeps it out of trivial constant folding.
 */
static inline int vmp_never0(uint32_t x) {
    static volatile uint32_t v = 0x9E3779B9u;
    uint32_t t = v + x;   /* x is dead here; keeps the predicate non-obvious */
    (void)x;
    return ((t * t) & 1u) == 0u;   /* parity of a square; guard sites are no-ops */
}

#endif /* VMP_OBF_H */
