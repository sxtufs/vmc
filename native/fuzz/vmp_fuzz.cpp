
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <functional>

#include "vmp_file.h"
#include "vmp_ir.h"
#include "vmp_sigblock.h"

void vmp_decryptInsns(uint8_t *, size_t, uint32_t) { }
void vmpNoteLazyFile() { }
void vmpLazyFileReady() { }

namespace {

typedef unsigned __int128 u128;

constexpr bool isPrime(unsigned n) {
    if (n < 2) return false;
    for (unsigned d = 2; (unsigned long long)d * d <= n; d++)
        if (n % d == 0) return false;
    return true;
}
constexpr unsigned nthPrime(unsigned k) {
    for (unsigned n = 2, seen = 0; ; n++)
        if (isPrime(n) && seen++ == k) return n;
}
constexpr uint64_t iSqrt(uint64_t n) {
    uint64_t lo = 0, hi = 1ull << 32;
    while (lo + 1 < hi) {
        uint64_t m = lo + (hi - lo) / 2;
        if ((u128)m * m <= n) lo = m; else hi = m;
    }
    return lo;
}
constexpr uint64_t sqrtScaled(uint64_t p) {
    const u128 target = (u128)p << 64;
    uint64_t lo = 0, hi = 1ull << 37;
    while (lo + 1 < hi) {
        uint64_t m = lo + (hi - lo) / 2;
        if ((u128)m * m <= target) lo = m; else hi = m;
    }
    return lo;
}
constexpr uint64_t cbrtScaled(uint64_t p) {
    const u128 target = (u128)p << 96;
    uint64_t lo = 0, hi = 1ull << 36;
    while (lo + 1 < hi) {
        uint64_t m = lo + (hi - lo) / 2;
        if ((u128)m * m * m <= target) lo = m; else hi = m;
    }
    return lo;
}
constexpr uint32_t shaH(unsigned i) {
    unsigned p = nthPrime(i);
    uint64_t x = sqrtScaled(p);
    return (uint32_t)(x - (iSqrt(p) << 32));
}
constexpr uint32_t shaK(unsigned i) {
    unsigned p = nthPrime(i);
    uint64_t y = cbrtScaled(p);
    uint64_t ic = 0; while ((ic + 1) * (ic + 1) * (ic + 1) <= p) ic++;
    return (uint32_t)(y - (ic << 32));
}

struct ShaConsts { uint32_t k[64]; uint32_t h[8]; };
constexpr ShaConsts shaConsts() {
    ShaConsts t{};
    for (unsigned i = 0; i < 64; i++) t.k[i] = shaK(i);
    for (unsigned i = 0; i < 8; i++) t.h[i] = shaH(i);
    return t;
}
constexpr const ShaConsts SC = shaConsts();

inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

void sha256Block(const uint8_t *p, uint32_t h[8]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16)
             | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
             e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + SC.k[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

}

bool vmpSha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8];
    for (int i = 0; i < 8; i++) h[i] = SC.h[i];
    const size_t padded = (len + 1 + 8 + 63) / 64 * 64;
    std::vector<uint8_t> buf(padded, 0);
    if (len) memcpy(buf.data(), data, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < padded; off += 64) sha256Block(&buf[off], h);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
    return true;
}

namespace {

struct Buf {
    std::vector<uint8_t> v;
    uint32_t pos() const { return (uint32_t)v.size(); }
    void u8(uint8_t b) { v.push_back(b); }
    void u16(uint16_t x) { u8(x); u8(x >> 8); }
    void u32(uint32_t x) { u16(x); u16(x >> 16); }
    void patch32(size_t off, uint32_t x) {
        for (int i = 0; i < 4; i++) v[off + i] = (uint8_t)(x >> (8 * i));
    }
    void put(const void *p, size_t n) {
        const uint8_t *b = (const uint8_t *)p;
        for (size_t i = 0; i < n; i++) u8(b[i]);
    }
    void zero(size_t n) { for (size_t i = 0; i < n; i++) u8(0); }
};

enum {
    HD_MAGIC = 0, HD_VERSION = 4, HD_FILE_SIZE = 8, HD_HDR_SIZE = 12,
    HD_ENDIAN = 16, HD_FEATURES = 20, HD_RESERVED = 24,
    HD_STRINGS = 28, HD_TYPES = 36, HD_PROTOS = 44, HD_FIELDS = 52,
    HD_METHODS = 60, HD_CODE = 68, HD_DATA = 76, HD_STRIDS = 84,
    HD_PERM = 92, HD_IR = 96, HD_IR_SIZE = 100,
};

struct Seeds {
    std::vector<uint32_t> strOff;
    uint32_t addStr(Buf &b, const char *s) {
        uint32_t off = b.pos();
        b.put(s, strlen(s) + 1);
        return off;
    }
};

void buildTables(Buf &b, bool sparse, bool protosLast = false) {
    auto sparseWrap = [&](uint32_t stride,
                          const std::vector<uint32_t> &keys,
                          const std::vector<uint8_t> &recs) {
        b.u32((uint32_t)keys.size());
        uint32_t recBase = 4 + 8 * (uint32_t)keys.size();
        for (size_t i = 0; i < keys.size(); i++) {
            b.u32(keys[i]);
            b.u32(recBase + (uint32_t)i * stride);
        }
        b.put(recs.data(), recs.size());
    };
    auto section = [&](uint32_t slot, const std::function<void(void)> &emit) {
        uint32_t off = b.pos();
        emit();
        b.patch32(slot, b.pos() - off);
        b.patch32(slot + 4, off);
    };

    const uint32_t base = 0;
    const uint32_t sEmpty = base + 0, sSeed = base + 1, sI = base + 8,
                 sV = base + 10, sSig = base + 12, sMeth = base + 17,
                 sFld = base + 27;

    section(HD_TYPES, [&](){
        uint32_t o[4] = { sSeed, sI, sV, sSig };
        if (!sparse) { for (int i = 0; i < 4; i++) b.u32(o[i]); }
        else {
            std::vector<uint32_t> keys = {0, 1, 2, 3};
            std::vector<uint8_t> recs;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++) recs.push_back(((uint8_t *)&o[i])[j]);
            sparseWrap(4, keys, recs);
        }
    });

    auto emitProtos = [&](){
        section(HD_PROTOS, [&](){
            if (!sparse) b.zero(12);
            else { std::vector<uint32_t> k = {0}; std::vector<uint8_t> r(12, 0); sparseWrap(12, k, r); }
        });
    };
    if (!protosLast) emitProtos();

    section(HD_FIELDS, [&](){
        Buf fr;
        fr.u16(0); fr.u16(1); fr.u32(sFld);
        if (!sparse) b.put(fr.v.data(), 8);
        else { std::vector<uint32_t> k = {0}; std::vector<uint8_t> r(fr.v.begin(), fr.v.end()); sparseWrap(8, k, r); }
    });

    section(HD_METHODS, [&](){
        Buf mr;
        mr.u16(0); mr.u16(0); mr.u32(sMeth);
        if (!sparse) b.put(mr.v.data(), 8);
        else { std::vector<uint32_t> k = {0}; std::vector<uint8_t> r(mr.v.begin(), mr.v.end()); sparseWrap(8, k, r); }
    });

    section(HD_CODE, [&](){
        b.u32(0); b.u32(0); b.u32(2); b.u32(2); b.u32(5);
        b.u32(1); b.u32(0); b.u32(0); b.u32(0);
    });

    section(HD_DATA, [&](){
        b.u16(0x000E);
        if (sparse) b.zero(14);
    });

    section(HD_STRIDS, [&](){
        if (!sparse) {
            uint32_t o[7] = { sEmpty, sSeed, sI, sV, sSig, sMeth, sFld };
            for (int i = 0; i < 7; i++) b.u32(o[i]);
        } else {
            b.u32(2);
            b.u32(0); b.u32(sEmpty);
            b.u32(1); b.u32(sSeed);
        }
    });
    if (protosLast) emitProtos();
}

void appendStrings(Buf &b) {
    b.u8(0);
    auto add = [&](const char *s) { b.put(s, strlen(s) + 1); };
    add("LSeed;"); add("I"); add("V"); add("(II)V");
    add("seedMethod"); add("x");
}

std::vector<uint8_t> buildV1() {
    Buf b;
    b.zero(112);
    uint32_t stringsOff = b.pos();
    appendStrings(b);
    uint32_t stringsSize = b.pos() - stringsOff;
    buildTables(b, false);
    b.patch32(HD_MAGIC, 0x32504D56u);
    b.patch32(HD_VERSION, 1);
    b.patch32(HD_FILE_SIZE, b.pos());
    b.patch32(HD_HDR_SIZE, 112);
    b.patch32(HD_ENDIAN, 0x12345678);
    b.patch32(HD_FEATURES, 0);
    b.patch32(HD_STRINGS, stringsSize); b.patch32(HD_STRINGS + 4, stringsOff);
    return b.v;
}

std::vector<uint8_t> buildV1ProtosEof() {
    Buf b;
    b.zero(112);
    uint32_t stringsOff = b.pos();
    appendStrings(b);
    uint32_t stringsSize = b.pos() - stringsOff;
    buildTables(b, false, true);
    b.patch32(HD_MAGIC, 0x32504D56u);
    b.patch32(HD_VERSION, 1);
    b.patch32(HD_FILE_SIZE, b.pos());
    b.patch32(HD_HDR_SIZE, 112);
    b.patch32(HD_ENDIAN, 0x12345678);
    b.patch32(HD_FEATURES, 0);
    b.patch32(HD_STRINGS, stringsSize); b.patch32(HD_STRINGS + 4, stringsOff);
    return b.v;
}

std::vector<uint8_t> buildV6() {
    Buf b;
    b.zero(112);
    uint32_t off, size;
    auto put = [&](Buf &sec) { off = b.pos(); size = sec.pos(); b.put(sec.v.data(), sec.v.size()); };

    Buf st; st.u8(0);
    auto addS = [&](const char *s) { uint32_t o = st.pos(); st.put(s, strlen(s) + 1); return o; };
    uint32_t sSeed = addS("LSeed;"), sI = addS("I"), sV = addS("V"),
             sSig = addS("(II)V"), sMeth = addS("seedMethod"), sFld = addS("x");
    uint32_t stringsOff, stringsSize;
    put(st);
    stringsOff = off; stringsSize = size;

    {
        Buf sec; sec.u32(4);
        uint32_t recs[4] = { sSeed, sI, sV, sSig };
        uint32_t recBase = 4 + 8 * 4;
        for (uint32_t i = 0; i < 4; i++) { sec.u32(i); sec.u32(recBase + i * 4); }
        for (uint32_t i = 0; i < 4; i++) sec.u32(recs[i]);
        put(sec); b.patch32(HD_TYPES, size); b.patch32(HD_TYPES + 4, off);
    }
    {
        Buf sec; sec.u32(1); sec.u32(0); sec.u32(4 + 8);
        for (int i = 0; i < 12; i++) sec.u8(0);
        put(sec); b.patch32(HD_PROTOS, size); b.patch32(HD_PROTOS + 4, off);
    }
    {
        Buf sec; sec.u32(1); sec.u32(0); sec.u32(12);
        sec.u16(0); sec.u16(1); sec.u32(sFld);
        put(sec); b.patch32(HD_FIELDS, size); b.patch32(HD_FIELDS + 4, off);
    }
    {
        Buf sec; sec.u32(1); sec.u32(0); sec.u32(12);
        sec.u16(0); sec.u16(0); sec.u32(sMeth);
        put(sec); b.patch32(HD_METHODS, size); b.patch32(HD_METHODS + 4, off);
    }
    {
        Buf sec;
        sec.u32(0); sec.u32(0); sec.u32(2); sec.u32(2); sec.u32(5);
        sec.u32(1); sec.u32(0); sec.u32(0); sec.u32(0);
        put(sec); b.patch32(HD_CODE, size); b.patch32(HD_CODE + 4, off);
    }
    uint32_t dataOff;
    {
        Buf sec; sec.u16(0x000E); sec.zero(14);
        put(sec); b.patch32(HD_DATA, size); b.patch32(HD_DATA + 4, off);
    }
    {
        Buf sec; sec.u32(2); sec.u32(0); sec.u32(0); sec.u32(1); sec.u32(sSeed);
        put(sec); b.patch32(HD_STRIDS, size); b.patch32(HD_STRIDS + 4, off);
    }
    {
        uint8_t canon[2] = { 0x0E, 0x00 };
        uint8_t dig[32]; vmpSha256(canon, 2, dig);
        Buf sec;
        sec.u32(1);
        sec.u32(4 + 4 * 1 + 4);
        sec.u32(0);
        sec.u16(1);
        sec.u16(1);
        sec.put(dig, 32);
        put(sec);
        b.patch32(HD_IR, off);
        b.patch32(HD_IR_SIZE, size);
    }
    {
        Buf sec;
        for (int l = 0; l < 8; l++) for (int i = 0; i < 256; i++) sec.u8(i);
        sec.u8(0);
        uint32_t idxBase = 2048 + 1;
        uint32_t rel = idxBase + 4;
        sec.u32(rel);
        sec.u16(1); sec.u16(0);
        put(sec); b.patch32(HD_PERM, off);
    }
    b.patch32(HD_MAGIC, 0x32504D56u);
    b.patch32(HD_VERSION, 6);
    b.patch32(HD_FILE_SIZE, b.pos());
    b.patch32(HD_HDR_SIZE, 112);
    b.patch32(HD_ENDIAN, 0x12345678);
    b.patch32(HD_FEATURES, 1);
    b.patch32(HD_STRINGS, stringsSize); b.patch32(HD_STRINGS + 4, stringsOff);
    return b.v;
}

bool writeFile(const char *path, const std::vector<uint8_t> &d) {
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    fwrite(d.data(), 1, d.size(), f);
    fclose(f);
    return true;
}

int digestFile(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "digest: cannot open %s\n", path); return 2; }
    std::vector<uint8_t> d;
    uint8_t b[4096]; size_t n;
    while ((n = fread(b, 1, sizeof(b), f)) > 0) d.insert(d.end(), b, b + n);
    fclose(f);
    uint8_t out[32];
    vmpSha256(d.data(), d.size(), out);
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}

uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

}

static void probe(VmpFile &f, const uint8_t *d, size_t n) {
    int mc = f.getMethodCount();
    if (mc > 64) mc = 64;
    for (int i = 0; i < mc; i++) {
        const VmMethod *m = f.getMethod(i);
        f.getMethodClass(i);
        f.getMethodName(i);
        f.getMethodShorty(i);
        f.getMethodSig(i);
        f.getProtoShorty(i);
        f.getProtoSig(i);
        f.getProtoPtr(i);
        uint32_t a, b, c;
        f.getFieldId(i, &a, &b, &c);
        f.getTypeDescriptor(i);
        f.getString(i);
        f.getStringById(i);
        f.codeIndexOfMethodId(i);
        f.getMethodByMethodId(i);
        if (m) { f.getInsns(m); f.getTries(m); }
    }
    if (n >= 16) {
        uint32_t x = le32(d + n - 4), y = le32(d + n - 8);
        uint32_t a, b, c;
        f.getStringById(x);
        f.getTypeDescriptor(y);
        f.getFieldId(x, &a, &b, &c);
        f.getProtoSig(y);
        const VmMethod *m = f.getMethod((int)(x % 65));
        if (m) f.getInsns(m);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    VmpFile f;
    if (!f.open(d, n)) return 0;
    probe(f, d, n);
    return 0;
}

#ifndef VMP_FUZZ_NO_CUSTOM_MAIN
int main(int argc, char **argv) {
    if (argc > 1 && strncmp(argv[1], "-dumpseed=", 10) == 0) {
        struct { const char *name; std::vector<uint8_t> bytes; } seeds[] = {
            { "v1_dense",        buildV1() },
            { "v6_full",         buildV6() },
            { "v1_protos_eof",   buildV1ProtosEof() },
        };
        bool all = true;
        for (auto &s : seeds) {
            char p[512];
            snprintf(p, sizeof(p), "%s/%s.bin", argv[1] + 10, s.name);
            bool wrote = writeFile(p, s.bytes);
            VmpFile f;
            bool opened = f.open(s.bytes.data(), s.bytes.size());
            printf("seed %s: %zu bytes, open %s, wrote %s\n", s.name,
                   s.bytes.size(), opened ? "OK" : "REJECT",
                   wrote ? "yes" : "NO");
            if (opened) probe(f, s.bytes.data(), s.bytes.size());
            all = all && wrote && opened;
        }
        fflush(stdout);
        return all ? 0 : 1;
    }
    if (argc > 2 && strcmp(argv[1], "-digest") == 0)
        return digestFile(argv[2]);
    fprintf(stderr, "vmp_seeds: use -dumpseed=DIR or -digest FILE\n"
                    "(the fuzzing binary is vmp_fuzz)\n");
    return 2;
}
#endif
