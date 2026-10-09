#include "vmp_ir.h"

#include <string.h>

static inline uint16_t irw(const uint16_t *widths, uint32_t j) {
    uint16_t v;
    memcpy(&v, (const uint8_t *)widths + 2u * j, 2);
    return (v >= 1 && v <= 8) ? v : 0;
}

size_t vmpIrPlainLen(const uint16_t *widths, uint32_t count) {
    size_t pos = 0;
    for (uint32_t j = 0; j < count; j++) pos += (size_t)irw(widths, j) * 2u;
    return pos;
}

void vmpIrExpand(uint8_t *reg, const uint16_t *widths, uint32_t count) {
    size_t pos = 0;
    for (uint32_t j = 0; j < count; j++) {
        const size_t n = (size_t)irw(widths, j) * 2u;
        memmove(reg + pos, reg + (size_t)j * 16u, n);
        pos += n;
    }
}
