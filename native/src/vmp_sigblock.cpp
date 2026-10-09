#include "vmp_sigblock.h"
#include "vmp_sha256_consts.h"
#include "vmp_log.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <vector>
#include <unistd.h>

static uint32_t g_k256[64];
static uint32_t g_h256[8];
static bool g_shaOk = false;


static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256Block(const uint8_t *p, uint32_t *h) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | (uint32_t)p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], k=h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = k + S1 + ch + g_k256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        k=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=k;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8];
    memcpy(h, g_h256, sizeof h);
    const uint8_t *p = data;
    size_t n = len;
    while (n >= 64) { sha256Block(p, h); p += 64; n -= 64; }
    uint8_t tail[128];
    memset(tail, 0, sizeof tail);
    memcpy(tail, p, n);
    tail[n] = 0x80;
    size_t tl = (n + 9 <= 64) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8u;
    for (int i = 0; i < 8; i++)
        tail[tl - 8 + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    for (size_t off = 0; off < tl; off += 64) sha256Block(tail + off, h);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(h[i] >> 24);
        out[4*i+1] = (uint8_t)(h[i] >> 16);
        out[4*i+2] = (uint8_t)(h[i] >> 8);
        out[4*i+3] = (uint8_t)h[i];
    }
}

static int shaVecOk(const uint8_t *msg, size_t len, const uint32_t *want) {
    uint8_t d[32];
    sha256(msg, len, d);
    for (int i = 0; i < 8; i++) {
        uint32_t w = ((uint32_t)d[4*i] << 24) | ((uint32_t)d[4*i+1] << 16) |
                     ((uint32_t)d[4*i+2] << 8) | (uint32_t)d[4*i+3];
        if (w != want[i]) return 0;
    }
    return 1;
}

static void shaSelfTest(void) {
    if (shaVecOk((const uint8_t *)"", 0, VMP_SHA_TEST_EMPTY) &&
        shaVecOk((const uint8_t *)"abc", 3, VMP_SHA_TEST_ABC))
        g_shaOk = true;
}

static bool shaReady(void) {
    static const bool ok = [] {
        memcpy(g_k256, VMP_SHA_K, sizeof g_k256);
        memcpy(g_h256, VMP_SHA_H0, sizeof g_h256);
        shaSelfTest();
        return g_shaOk;
    }();
    return ok;
}

bool vmpSha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    if (!shaReady()) return false;
    sha256(data, len, out);
    return true;
}

static void vmp_wipe_local(void *p, size_t n) {
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}

static bool vmpHmacRaw(const uint8_t *key, size_t klen,
                       const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    uint8_t k0[64], inner[32], outer[64 + 32];
    if (klen > 64) {
        sha256(key, klen, k0);
        memset(k0 + 32, 0, 32);
    } else {
        memcpy(k0, key, klen);
        memset(k0 + klen, 0, 64 - klen);
    }
    uint8_t *ipadBuf = (uint8_t *)malloc(64 + mlen);
    if (!ipadBuf) return false;
    for (int i = 0; i < 64; i++) ipadBuf[i] = (uint8_t)(k0[i] ^ 0x36);
    memcpy(ipadBuf + 64, msg, mlen);
    sha256(ipadBuf, 64 + mlen, inner);
    free(ipadBuf);
    for (int i = 0; i < 64; i++) outer[i] = (uint8_t)(k0[i] ^ 0x5c);
    memcpy(outer + 64, inner, 32);
    sha256(outer, sizeof(outer), out);
    { volatile uint8_t *q = k0;
      for (size_t i = 0; i < sizeof k0; i++) q[i] = 0;
      q = outer;
      for (size_t i = 0; i < sizeof outer; i++) q[i] = 0; }
    return true;
}

static bool g_hmacOk = false;

static void hmacSelfTest(void) {
    uint8_t o[2][32];
    if (!vmpHmacRaw(VMP_HMAC_K1, sizeof VMP_HMAC_K1,
                    VMP_HMAC_M1, sizeof VMP_HMAC_M1, o[0])) return;
    if (!vmpHmacRaw(VMP_HMAC_K2, sizeof VMP_HMAC_K2,
                    VMP_HMAC_M2, sizeof VMP_HMAC_M2, o[1])) return;
    const uint32_t *want[2] = { VMP_HMAC_T1, VMP_HMAC_T2 };
    for (int j = 0; j < 2; j++)
        for (int i = 0; i < 8; i++) {
            uint32_t got = ((uint32_t)o[j][4 * i] << 24) |
                           ((uint32_t)o[j][4 * i + 1] << 16) |
                           ((uint32_t)o[j][4 * i + 2] << 8) |
                            (uint32_t)o[j][4 * i + 3];
            if (got != want[j][i]) { vmp_wipe_local(o[j], 32); return; }
        }
    vmp_wipe_local(o[0], 32); vmp_wipe_local(o[1], 32);
    g_hmacOk = true;
}

bool vmpHmacSha256(const uint8_t *key, size_t klen,
                   const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    if (!shaReady()) return false;
    static const bool hmacOk = [] { hmacSelfTest(); return g_hmacOk; }();
    if (!hmacOk) {
        LOGDIAG("vmp-hmac: HMAC self-test FAILED - auth refuses");
        return false;
    }
    return vmpHmacRaw(key, klen, msg, mlen, out);
}

static inline uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct { const uint8_t *p; size_t cap; size_t off; } Rd;

static bool rdU32(Rd *r, uint32_t *v) {
    if (r->off + 4 > r->cap) return false;
    *v = le32(r->p + r->off);
    r->off += 4;
    return true;
}
static bool rdTake(Rd *r, size_t n, Rd *sub) {
    if (n > r->cap - r->off) return false;
    sub->p = r->p + r->off; sub->cap = n; sub->off = 0;
    r->off += n;
    return true;
}
static bool rdSub(Rd *r, Rd *sub) {
    uint32_t n;
    if (!rdU32(r, &n)) return false;
    return rdTake(r, n, sub);
}

static bool derLen(const uint8_t *p, size_t avail, size_t *hdr, size_t *len) {
    if (avail < 2) return false;
    if (p[1] < 0x80)          { *hdr = 2; *len = p[1]; }
    else if (p[1] == 0x81)    { if (avail < 3) return false; *hdr = 3; *len = p[2]; }
    else if (p[1] == 0x82)    { if (avail < 4) return false; *hdr = 4;
                                 *len = ((size_t)p[2] << 8) | p[3]; }
    else return false;
    return true;
}

static bool parseSigBlock(const uint8_t *base, size_t size,
                          uint8_t out[32], bool *noSigBlock, int *reason,
                          uint32_t *dbg) {
    *noSigBlock = false;
    *reason = 0;
    memset(dbg, 0, 9 * sizeof(uint32_t));
    if (size < 64) { *noSigBlock = true; *reason = 2; return false; }

    const size_t first = (size > 22 + 65535) ? size - 22 - 65535 : 0;
    const uint8_t *eocd = NULL;
    for (size_t off = size - 22; ; off--) {
        if (le32(base + off) == 0x06054b50u) { eocd = base + off; break; }
        if (off == first) break;
    }
    if (!eocd) { *noSigBlock = true; *reason = 3; return false; }

    uint32_t cdOff = le32(eocd + 16);
    if (cdOff == 0xFFFFFFFFu || cdOff < 24 || cdOff > size) { *noSigBlock = true; *reason = 4; return false; }

    static const char kMagic[16] =
        { 'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2' };
    if (memcmp(base + cdOff - 16, kMagic, 16) != 0) { *noSigBlock = true; *reason = 5; return false; }

    uint32_t blockLo = le32(base + cdOff - 24);
    uint32_t blockHi = le32(base + cdOff - 20);
    if (blockHi != 0 || blockLo < 24 || (size_t)blockLo + 8 + 16 > (size_t)cdOff)
        { *reason = 6; return false; }
    size_t blockStart = (size_t)cdOff - 8 - (size_t)blockLo;
    if (le32(base + blockStart) != blockLo
            || le32(base + blockStart + 4) != blockHi)
        { *reason = 6; return false; }

    size_t pEnd = cdOff - 24;
    dbg[7] = (uint32_t)blockStart;
    dbg[8] = (uint32_t)pEnd;
    const uint8_t *v2 = NULL; size_t v2l = 0;
    const uint8_t *v3 = NULL; size_t v3l = 0;
    const uint8_t *v31 = NULL; size_t v31l = 0;
    size_t p = blockStart + 8;
    uint32_t visited = 0;
    while (p + 8 <= pEnd) {
        uint32_t w0 = le32(base + p);
        uint32_t id = le32(base + p + 4);
        if (visited == 0) { dbg[1] = w0; dbg[2] = id; }
        if (visited == 1) { dbg[3] = w0; dbg[4] = id; }
        visited++;
        const int isScheme = (id == 0x7109871au || id == 0xf05368c0u ||
                              id == 0x1b54e549u);
        if (isScheme) {
            if (w0 < 4 || p + 4 + (size_t)w0 > pEnd) { dbg[5] = (uint32_t)p; break; }
            const uint8_t *val = base + p + 8;
            size_t vlen = (size_t)w0 - 4;
            if      (id == 0x7109871au && !v2)  { v2  = val; v2l  = vlen; }
            else if (id == 0xf05368c0u && !v3)  { v3  = val; v3l  = vlen; }
            else if (id == 0x1b54e549u && !v31) { v31 = val; v31l = vlen; }
            p += 4 + (size_t)w0;
            continue;
        }
        if (id == 0 && w0 >= 8 && p + 8 + (size_t)w0 <= pEnd) {
            const uint8_t *val = base + p + 8;
            uint32_t sid = le32(val);
            uint32_t slen = le32(val + 4);
            if ((uint64_t)slen + 8 <= (uint64_t)w0) {
                const uint8_t *inner = val + 8;
                if      (sid == 0x7109871au && !v2)  { v2  = inner; v2l  = slen; dbg[5] = (uint32_t)p; }
                else if (sid == 0xf05368c0u && !v3)  { v3  = inner; v3l  = slen; dbg[5] = (uint32_t)p; }
                else if (sid == 0x1b54e549u && !v31) { v31 = inner; v31l = slen; dbg[5] = (uint32_t)p; }
            }
            p += 8 + (size_t)w0;
            continue;
        }
        if (w0 < 4 || p + 4 + (size_t)w0 > pEnd) { dbg[5] = (uint32_t)p; break; }
        p += 4 + (size_t)w0;
    }
    dbg[0] = visited;

    const uint8_t *sd; size_t sl;
    if      (v2)  { sd = v2;  sl = v2l; }
    else if (v3)  { sd = v3;  sl = v3l; }
    else if (v31) { sd = v31; sl = v31l; }
    else {
        *reason = 7;
        size_t hp = blockStart + 8;
        for (size_t i = 0; i < 32 && hp + (i + 4) * 4 <= pEnd; i += 4) {
            LOGDIAG("vmp-init: pkw +%03x: %08x %08x %08x %08x",
                    (uint32_t)(i * 4),
                    le32(base + hp + (i + 0) * 4), le32(base + hp + (i + 1) * 4),
                    le32(base + hp + (i + 2) * 4), le32(base + hp + (i + 3) * 4));
        }
        if (pEnd >= hp + 48) {
            size_t tp = pEnd - 32;
            LOGDIAG("vmp-init: pkend: %08x %08x %08x %08x",
                    le32(base + tp), le32(base + tp + 4),
                    le32(base + tp + 8), le32(base + tp + 12));
        }
        return false;
    }

    Rd s1 = { sd, sl, 0 }, signers, signer, sdata, digests, certs;
    if (!rdSub(&s1, &signers)) { *reason = 8; return false; }
    if (!rdSub(&signers, &signer)) { *reason = 8; return false; }
    if (!rdSub(&signer, &sdata)) { *reason = 8; return false; }
    if (!rdSub(&sdata, &digests)) { *reason = 8; return false; }
    if (!rdSub(&sdata, &certs) && !rdSub(&signer, &certs)) { *reason = 8; return false; }

    if (certs.cap >= 8 && certs.p[0] != 0x30) {
        uint32_t cl = le32(certs.p);
        if ((uint64_t)cl + 4 <= (uint64_t)certs.cap && certs.p[4] == 0x30) {
            certs.p += 4;
            certs.cap -= 4;
        }
    }
    if (certs.cap < 4 || certs.p[0] != 0x30) { *reason = 8; return false; }
    size_t h1, l1;
    if (!derLen(certs.p, certs.cap, &h1, &l1)) { *reason = 8; return false; }
    if (h1 + l1 > certs.cap || h1 + l1 < 8) { *reason = 8; return false; }
    if (certs.p[h1] != 0x30) { *reason = 8; return false; }

    if (!shaReady()) { *noSigBlock = true; *reason = 1; return false; }
    sha256(certs.p, h1 + l1, out);
    return true;
}

static bool vmpGetSourceDir(JNIEnv *env, jobject ctx, char *buf, size_t cap) {
    bool ok = false;
    if (env->PushLocalFrame(8) != 0) return false;
    do {
        jclass ctxCls = env->GetObjectClass(ctx);
        if (!ctxCls) break;
        jmethodID mGetAi = env->GetMethodID(ctxCls, "getApplicationInfo",
                "()Landroid/content/pm/ApplicationInfo;");
        if (!mGetAi) { if (env->ExceptionCheck()) env->ExceptionClear(); break; }
        jobject ai = env->CallObjectMethod(ctx, mGetAi);
        if (!ai || env->ExceptionCheck()) { env->ExceptionClear(); break; }
        jclass aiCls = env->GetObjectClass(ai);
        jfieldID fSd = aiCls ? env->GetFieldID(aiCls, "sourceDir",
                "Ljava/lang/String;") : nullptr;
        if (!fSd) { if (env->ExceptionCheck()) env->ExceptionClear(); break; }
        jstring s = (jstring)env->GetObjectField(ai, fSd);
        if (!s) break;
        const char *u = env->GetStringUTFChars(s, nullptr);
        if (!u) { env->ExceptionClear(); break; }
        size_t l = strlen(u);
        if (l > 0 && l + 1 <= cap) { memcpy(buf, u, l + 1); ok = true; }
        env->ReleaseStringUTFChars(s, u);
    } while (false);
    if (!ok) env->ExceptionClear();
    env->PopLocalFrame(nullptr);
    return ok;
}


static bool readFullyAt(int fd, uint8_t *dst, size_t size, off_t offset) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, dst + done, size - done, offset + (off_t)done);
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static void putLe32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

bool vmpReadFileCertDigest(JNIEnv *env, jobject ctx, uint8_t out[32],
                           bool *noSigBlock, int *reason, uint32_t *dbg) {
    *noSigBlock = false;
    *reason = 0;
    if (!shaReady()) { *noSigBlock = true; *reason = 1; return false; }
    char path[512];
    if (!vmpGetSourceDir(env, ctx, path, sizeof path)) { *reason = 10; return false; }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { *reason = 10; return false; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 64 ||
            (uint64_t)st.st_size > 1024ull * 1024ull * 1024ull) {
        close(fd);
        *reason = 10;
        return false;
    }

    struct stat stPath;
    if (stat(path, &stPath) != 0) {
        close(fd);
        *reason = 10;
        return false;
    }
    if (stPath.st_dev != st.st_dev || stPath.st_ino != st.st_ino) {
        close(fd);
        *reason = 12;
        return false;
    }

    const size_t fileSize = (size_t)st.st_size;
    const size_t eocdWindow = 22u + 65535u;
    const size_t tailStart = fileSize > eocdWindow ? fileSize - eocdWindow : 0;
    const size_t tailSize = fileSize - tailStart;
    std::vector<uint8_t> tail(tailSize);
    if (!readFullyAt(fd, tail.data(), tail.size(), (off_t)tailStart)) {
        close(fd);
        *reason = 10;
        return false;
    }

    const uint8_t *eocd = nullptr;
    for (size_t off = tailSize - 22; ; off--) {
        if (le32(tail.data() + off) == 0x06054b50u) {
            eocd = tail.data() + off;
            break;
        }
        if (off == 0) break;
    }
    if (!eocd) {
        close(fd);
        *noSigBlock = true;
        *reason = 3;
        return false;
    }

    const uint32_t cdOff = le32(eocd + 16);
    if (cdOff == 0xFFFFFFFFu || cdOff < 24 || (uint64_t)cdOff > fileSize) {
        close(fd);
        *noSigBlock = true;
        *reason = 4;
        return false;
    }

    uint8_t meta[24];
    if (!readFullyAt(fd, meta, sizeof meta, (off_t)cdOff - 24)) {
        close(fd);
        *reason = 10;
        return false;
    }
    static const char kMagic[16] =
        { 'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2' };
    if (memcmp(meta + 8, kMagic, sizeof kMagic) != 0) {
        close(fd);
        *noSigBlock = true;
        *reason = 5;
        return false;
    }
    const uint32_t blockSize = le32(meta);
    const uint32_t blockHi = le32(meta + 4);
    static const uint32_t MAX_SIGNING_BLOCK_BYTES = 64u * 1024u * 1024u;
    if (blockHi != 0 || blockSize < 24 || blockSize > MAX_SIGNING_BLOCK_BYTES ||
            (uint64_t)blockSize + 8u + 16u > cdOff) {
        close(fd);
        *reason = 6;
        return false;
    }
    const size_t blockBytes = (size_t)blockSize + 8u;
    std::vector<uint8_t> block(blockBytes);
    const off_t blockStart = (off_t)cdOff - 8 - (off_t)blockSize;
    if (!readFullyAt(fd, block.data(), block.size(), blockStart)) {
        close(fd);
        *reason = 10;
        return false;
    }
    close(fd);

    const size_t compactPrefix = 64u;
    std::vector<uint8_t> compact(compactPrefix + blockBytes + 22u, 0);
    memcpy(compact.data() + compactPrefix, block.data(), block.size());
    const size_t compactEocd = compactPrefix + blockBytes;
    putLe32(compact.data() + compactEocd, 0x06054b50u);
    putLe32(compact.data() + compactEocd + 16, (uint32_t)blockBytes + (uint32_t)compactPrefix);
    return parseSigBlock(compact.data(), compact.size(), out,
                         noSigBlock, reason, dbg);
}
