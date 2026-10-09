#include "vmp_apk_verify.h"

#include "vmp_log.h"
#include "vmp_sigblock.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace {

static const uint32_t V2_BLOCK_ID = 0x7109871aU;
static const uint32_t V3_BLOCK_ID = 0xf05368c0U;
static const uint32_t V31_BLOCK_ID = 0x1b54e549U;
static const size_t APK_CHUNK = 1u << 20;
static const uint64_t MAX_APK = 1024ull * 1024ull * 1024ull;
static const uint64_t MAX_BLOCK = 64ull * 1024ull * 1024ull;

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
static inline void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

struct Reader {
    const uint8_t *p;
    size_t n;
    size_t off;

    bool u32(uint32_t *out) {
        if (off > n || n - off < 4) return false;
        *out = rd32(p + off); off += 4; return true;
    }
    bool lp(const uint8_t **out, size_t *len) {
        uint32_t size = 0;
        if (!u32(&size) || (uint64_t)size > (uint64_t)(n - off)) return false;
        *out = p + off; *len = size; off += size; return true;
    }
    bool sub(Reader *out) {
        const uint8_t *q = nullptr; size_t len = 0;
        if (!lp(&q, &len)) return false;
        out->p = q; out->n = len; out->off = 0; return true;
    }
    bool empty() const { return off == n; }
};

struct ApkLayout {
    int fd = -1;
    size_t fileSize = 0;
    uint32_t centralDirOffset = 0;
    size_t eocdOffset = 0;
    size_t signingBlockOffset = 0;
    std::vector<uint8_t> eocd;
    std::vector<uint8_t> signingBlock;
};

static bool getSourceDir(JNIEnv *env, jobject ctx, char out[512]) {
    if (!ctx || env->PushLocalFrame(12) != 0) return false;
    bool ok = false;
    do {
        jclass ctxCls = env->GetObjectClass(ctx);
        jmethodID getAi = ctxCls ? env->GetMethodID(ctxCls, "getApplicationInfo",
                "()Landroid/content/pm/ApplicationInfo;") : nullptr;
        if (!getAi) break;
        jobject ai = env->CallObjectMethod(ctx, getAi);
        if (!ai || env->ExceptionCheck()) break;
        jclass aiCls = env->GetObjectClass(ai);
        jfieldID sourceDir = aiCls ? env->GetFieldID(aiCls, "sourceDir",
                "Ljava/lang/String;") : nullptr;
        if (!sourceDir) break;
        jstring path = (jstring)env->GetObjectField(ai, sourceDir);
        if (!path) break;
        const char *utf = env->GetStringUTFChars(path, nullptr);
        if (!utf) break;
        size_t len = strlen(utf);
        if (len > 0 && len + 1 < 512) {
            memcpy(out, utf, len + 1); ok = true;
        }
        env->ReleaseStringUTFChars(path, utf);
    } while (false);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->PopLocalFrame(nullptr);
    return ok;
}

static bool readAt(int fd, uint8_t *dst, size_t len, off_t offset) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, dst + done, len - done, offset + (off_t)done);
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool loadLayout(JNIEnv *env, jobject ctx, ApkLayout *out, int *reason) {
    char path[512];
    if (!getSourceDir(env, ctx, path)) { *reason = 10; return false; }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { *reason = 10; return false; }

    struct stat st;
    struct stat stPath;
    if (fstat(fd, &st) != 0 || stat(path, &stPath) != 0 ||
        st.st_dev != stPath.st_dev || st.st_ino != stPath.st_ino ||
        st.st_size < 64 || (uint64_t)st.st_size > MAX_APK) {
        close(fd); *reason = 10; return false;
    }
    size_t fileSize = (size_t)st.st_size;
    size_t tailStart = fileSize > 22u + 65535u ? fileSize - 22u - 65535u : 0;
    size_t tailSize = fileSize - tailStart;
    std::vector<uint8_t> tail(tailSize);
    if (!readAt(fd, tail.data(), tail.size(), (off_t)tailStart)) {
        close(fd); *reason = 10; return false;
    }

    const uint8_t *eocd = nullptr;
    size_t eocdRel = 0;
    for (size_t off = tailSize - 22; ; off--) {
        if (rd32(tail.data() + off) == 0x06054b50U) {
            uint16_t comment = rd16(tail.data() + off + 20);
            if (off + 22u + comment == tailSize) {
                eocd = tail.data() + off; eocdRel = off; break;
            }
        }
        if (off == 0) break;
    }
    if (!eocd) { close(fd); *reason = 3; return false; }

    uint32_t cdOffset = rd32(eocd + 16);
    uint32_t cdSize = rd32(eocd + 12);
    size_t eocdOffset = tailStart + eocdRel;
    if (cdOffset == 0xffffffffU || cdSize == 0xffffffffU ||
        cdOffset < 24 || (uint64_t)cdOffset + cdSize != eocdOffset) {
        close(fd); *reason = 4; return false;
    }

    uint8_t meta[24];
    if (!readAt(fd, meta, sizeof(meta), (off_t)cdOffset - 24)) {
        close(fd); *reason = 10; return false;
    }
    static const uint8_t magic[16] = {
        'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2'
    };
    uint64_t blockSize = rd64(meta);
    if (memcmp(meta + 8, magic, 16) != 0 || blockSize < 24 ||
        blockSize > MAX_BLOCK || blockSize + 8u + 16u > cdOffset) {
        close(fd); *reason = 5; return false;
    }
    size_t blockBytes = (size_t)blockSize + 8u;
    size_t blockStart = (size_t)cdOffset - 8u - (size_t)blockSize;
    std::vector<uint8_t> block(blockBytes);
    if (!readAt(fd, block.data(), block.size(), (off_t)blockStart)) {
        close(fd); *reason = 10; return false;
    }
    if (rd64(block.data()) != blockSize ||
        rd64(block.data() + blockBytes - 24) != blockSize ||
        memcmp(block.data() + blockBytes - 16, magic, 16) != 0) {
        close(fd); *reason = 6; return false;
    }

    out->fd = fd;
    out->fileSize = fileSize;
    out->centralDirOffset = cdOffset;
    out->eocdOffset = eocdOffset;
    out->signingBlockOffset = blockStart;
    out->eocd.assign(eocd, eocd + 22u + rd16(eocd + 20));
    out->signingBlock.swap(block);
    return true;
}

/* Returns 1 when found, 0 when absent, -1 when the pair area is malformed. */
static int findPair(const std::vector<uint8_t> &block, uint32_t wanted,
                    const uint8_t **value, size_t *valueLen) {
    if (block.size() < 32) return -1;
    size_t p = 8;
    size_t end = block.size() - 24;
    bool found = false;
    while (p < end) {
        if (end - p < 8) return -1;
        uint64_t pairLen = rd64(block.data() + p);
        if (pairLen < 4 || pairLen > (uint64_t)(end - p - 8)) return -1;
        uint32_t id = rd32(block.data() + p + 8);
        if (id == wanted) {
            if (found) return -1;
            found = true;
            *value = block.data() + p + 12;
            *valueLen = (size_t)pairLen - 4u;
        }
        p += 8u + (size_t)pairLen;
    }
    return found ? 1 : 0;
}

struct Alg {
    uint32_t id;
    const char *signature;
    const char *digest;
    int digestBytes;
    int rank;
    bool pss;
    int saltBytes;
};

static bool algorithm(uint32_t id, Alg *out) {
    switch (id) {
        case 0x0101: *out = {id, "SHA256withRSA/PSS", "SHA-256", 32, 70, true, 32}; return true;
        case 0x0102: *out = {id, "SHA512withRSA/PSS", "SHA-512", 64, 80, true, 64}; return true;
        case 0x0103: *out = {id, "SHA256withRSA", "SHA-256", 32, 60, false, 0}; return true;
        case 0x0104: *out = {id, "SHA512withRSA", "SHA-512", 64, 65, false, 0}; return true;
        case 0x0201: *out = {id, "SHA256withECDSA", "SHA-256", 32, 50, false, 0}; return true;
        case 0x0202: *out = {id, "SHA512withECDSA", "SHA-512", 64, 55, false, 0}; return true;
        case 0x0301: *out = {id, "SHA256withDSA", "SHA-256", 32, 40, false, 0}; return true;
        default: return false;
    }
}

struct AlgRecord { uint32_t id; const uint8_t *data; size_t len; };

static bool parseAlgRecords(const uint8_t *p, size_t n, std::vector<AlgRecord> *out) {
    Reader list{p, n, 0};
    while (!list.empty()) {
        Reader record{nullptr, 0, 0};
        if (!list.sub(&record)) return false;
        uint32_t id = 0; const uint8_t *data = nullptr; size_t len = 0;
        if (!record.u32(&id) || !record.lp(&data, &len) || !record.empty()) return false;
        out->push_back({id, data, len});
    }
    return true;
}

static bool getSdkInt(JNIEnv *env, int *sdk) {
    jclass cls = env->FindClass("android/os/Build$VERSION");
    if (!cls) { env->ExceptionClear(); return false; }
    jfieldID f = env->GetStaticFieldID(cls, "SDK_INT", "I");
    if (!f) { env->ExceptionClear(); env->DeleteLocalRef(cls); return false; }
    *sdk = env->GetStaticIntField(cls, f);
    env->DeleteLocalRef(cls);
    return !env->ExceptionCheck();
}

static jbyteArray makeBytes(JNIEnv *env, const uint8_t *p, size_t n) {
    if (n > 0x7fffffffU) return nullptr;
    jbyteArray result = env->NewByteArray((jsize)n);
    if (!result) return nullptr;
    if (n) env->SetByteArrayRegion(result, 0, (jsize)n, (const jbyte *)p);
    return result;
}

static bool verifyJavaSignature(JNIEnv *env, const Alg &alg,
                               const uint8_t *certDer, size_t certLen,
                               const uint8_t *publicKey, size_t publicKeyLen,
                               const uint8_t *signedData, size_t signedDataLen,
                               const uint8_t *signature, size_t signatureLen,
                               uint8_t certDigest[32]) {
    if (env->PushLocalFrame(96) != 0) return false;
    auto fail = [&]() -> bool {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return false;
    };

    jclass cfCls = env->FindClass("java/security/cert/CertificateFactory");
    jclass baisCls = env->FindClass("java/io/ByteArrayInputStream");
    if (!cfCls || !baisCls) return fail();
    jmethodID cfGet = env->GetStaticMethodID(cfCls, "getInstance",
            "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jmethodID baisCtor = env->GetMethodID(baisCls, "<init>", "([B)V");
    if (!cfGet || !baisCtor) return fail();
    jstring x509 = env->NewStringUTF("X.509");
    jbyteArray certArray = makeBytes(env, certDer, certLen);
    if (!x509 || !certArray) return fail();
    jobject factory = env->CallStaticObjectMethod(cfCls, cfGet, x509);
    jobject input = env->NewObject(baisCls, baisCtor, certArray);
    jmethodID generate = env->GetMethodID(cfCls, "generateCertificate",
            "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");
    if (!factory || !input || !generate) return fail();
    jobject cert = env->CallObjectMethod(factory, generate, input);
    if (!cert || env->ExceptionCheck()) return fail();

    if (!vmpSha256(certDer, certLen, certDigest)) return fail();
    jclass certCls = env->GetObjectClass(cert);
    jmethodID getKey = certCls ? env->GetMethodID(certCls, "getPublicKey",
            "()Ljava/security/PublicKey;") : nullptr;
    if (!getKey) return fail();
    jobject key = env->CallObjectMethod(cert, getKey);
    if (!key || env->ExceptionCheck()) return fail();
    jclass keyCls = env->GetObjectClass(key);
    jmethodID keyEncoded = keyCls ? env->GetMethodID(keyCls, "getEncoded", "()[B") : nullptr;
    if (!keyEncoded) return fail();
    jbyteArray keyBytes = (jbyteArray)env->CallObjectMethod(key, keyEncoded);
    if (!keyBytes || env->ExceptionCheck() ||
        (size_t)env->GetArrayLength(keyBytes) != publicKeyLen) return fail();
    std::vector<uint8_t> keyCopy(publicKeyLen);
    env->GetByteArrayRegion(keyBytes, 0, (jsize)publicKeyLen, (jbyte *)keyCopy.data());
    if (!std::equal(keyCopy.begin(), keyCopy.end(), publicKey)) return fail();

    jclass sigCls = env->FindClass("java/security/Signature");
    if (!sigCls) return fail();
    jmethodID sigGet = env->GetStaticMethodID(sigCls, "getInstance",
            "(Ljava/lang/String;)Ljava/security/Signature;");
    jmethodID initVerify = env->GetMethodID(sigCls, "initVerify",
            "(Ljava/security/PublicKey;)V");
    jmethodID update = env->GetMethodID(sigCls, "update", "([B)V");
    jmethodID verify = env->GetMethodID(sigCls, "verify", "([B)Z");
    if (!sigGet || !initVerify || !update || !verify) return fail();
    jstring sigName = env->NewStringUTF(alg.signature);
    jobject sig = sigName ? env->CallStaticObjectMethod(sigCls, sigGet, sigName) : nullptr;
    if (!sig || env->ExceptionCheck()) return fail();

    env->CallVoidMethod(sig, initVerify, key);
    if (env->ExceptionCheck()) return fail();

    if (alg.pss) {
        jclass pssCls = env->FindClass("java/security/spec/PSSParameterSpec");
        jclass mgfCls = env->FindClass("java/security/spec/MGF1ParameterSpec");
        if (!pssCls || !mgfCls) return fail();
        jmethodID mgfCtor = env->GetMethodID(mgfCls, "<init>", "(Ljava/lang/String;)V");
        jmethodID pssCtor = env->GetMethodID(pssCls, "<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/security/spec/AlgorithmParameterSpec;II)V");
        jmethodID setParam = env->GetMethodID(sigCls, "setParameter",
                "(Ljava/security/spec/AlgorithmParameterSpec;)V");
        if (!mgfCtor || !pssCtor || !setParam) return fail();
        jstring digestName = env->NewStringUTF(alg.digest);
        jstring mgfName = env->NewStringUTF("MGF1");
        jobject mgf = digestName ? env->NewObject(mgfCls, mgfCtor, digestName) : nullptr;
        jobject pss = (digestName && mgfName && mgf)
                ? env->NewObject(pssCls, pssCtor, digestName, mgfName, mgf,
                                 alg.saltBytes, 1)
                : nullptr;
        if (!pss) return fail();
        env->CallVoidMethod(sig, setParam, pss);
        if (env->ExceptionCheck()) return fail();
    }

    jbyteArray signedArray = makeBytes(env, signedData, signedDataLen);
    jbyteArray signatureArray = makeBytes(env, signature, signatureLen);
    if (!signedArray || !signatureArray) return fail();
    env->CallVoidMethod(sig, update, signedArray);
    if (env->ExceptionCheck()) return fail();
    jboolean verified = env->CallBooleanMethod(sig, verify, signatureArray);
    if (env->ExceptionCheck() || verified != JNI_TRUE) return fail();
    env->PopLocalFrame(nullptr);
    return true;
}

struct MdState {
    jobject object;
    jmethodID update;
    jmethodID digest;
    int outputLen;
};

static bool newMd(JNIEnv *env, jclass cls, jmethodID get, const char *name,
                  MdState *out) {
    jstring alg = env->NewStringUTF(name);
    if (!alg) return false;
    out->object = env->CallStaticObjectMethod(cls, get, alg);
    return out->object != nullptr && !env->ExceptionCheck();
}

static bool mdUpdate(JNIEnv *env, const MdState &md, const uint8_t *p, size_t n) {
    jbyteArray bytes = makeBytes(env, p, n);
    if (!bytes) return false;
    env->CallVoidMethod(md.object, md.update, bytes);
    env->DeleteLocalRef(bytes);
    return !env->ExceptionCheck();
}

static bool mdDigest(JNIEnv *env, const MdState &md, std::vector<uint8_t> *out) {
    jbyteArray result = (jbyteArray)env->CallObjectMethod(md.object, md.digest);
    if (!result || env->ExceptionCheck() || env->GetArrayLength(result) != md.outputLen)
        return false;
    out->resize((size_t)md.outputLen);
    env->GetByteArrayRegion(result, 0, md.outputLen, (jbyte *)out->data());
    env->DeleteLocalRef(result);
    return !env->ExceptionCheck();
}

static bool computeContentDigest(JNIEnv *env, const ApkLayout &layout,
                                 const Alg &alg, std::vector<uint8_t> *out) {
    if (env->PushLocalFrame(64) != 0) return false;
    auto fail = [&]() -> bool {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->PopLocalFrame(nullptr); return false;
    };
    jclass mdCls = env->FindClass("java/security/MessageDigest");
    if (!mdCls) return fail();
    jmethodID get = env->GetStaticMethodID(mdCls, "getInstance",
            "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jmethodID update = env->GetMethodID(mdCls, "update", "([B)V");
    jmethodID digest = env->GetMethodID(mdCls, "digest", "()[B");
    if (!get || !update || !digest) return fail();
    MdState chunkMd{}, topMd{};
    if (!newMd(env, mdCls, get, alg.digest, &chunkMd) ||
        !newMd(env, mdCls, get, alg.digest, &topMd)) return fail();
    chunkMd.update = update; chunkMd.digest = digest; chunkMd.outputLen = alg.digestBytes;
    topMd.update = update; topMd.digest = digest; topMd.outputLen = alg.digestBytes;

    struct Range { uint64_t off; uint64_t len; const uint8_t *memory; };
    std::vector<uint8_t> eocd = layout.eocd;
    if (eocd.size() < 22) return fail();
    put32(eocd.data() + 16, (uint32_t)layout.signingBlockOffset);
    Range ranges[3] = {
        {0, layout.signingBlockOffset, nullptr},
        {layout.centralDirOffset, layout.eocdOffset - layout.centralDirOffset, nullptr},
        {0, eocd.size(), eocd.data()}
    };
    uint64_t chunks = 0;
    for (const Range &r : ranges)
        chunks += r.len == 0 ? 0 : (r.len + APK_CHUNK - 1) / APK_CHUNK;
    if (chunks > 0xffffffffU) return fail();
    std::vector<uint8_t> chunk(APK_CHUNK);
    std::vector<uint8_t> chunkDigests;
    chunkDigests.reserve((size_t)chunks * (size_t)alg.digestBytes);

    for (const Range &r : ranges) {
        uint64_t pos = 0;
        while (pos < r.len) {
            size_t n = (size_t)std::min<uint64_t>(APK_CHUNK, r.len - pos);
            const uint8_t *data = nullptr;
            if (r.memory) {
                data = r.memory + pos;
            } else {
                if (!readAt(layout.fd, chunk.data(), n, (off_t)(r.off + pos))) return fail();
                data = chunk.data();
            }
            uint8_t header[5] = {0xa5, 0, 0, 0, 0};
            put32(header + 1, (uint32_t)n);
            if (!mdUpdate(env, chunkMd, header, sizeof(header)) ||
                !mdUpdate(env, chunkMd, data, n)) return fail();
            std::vector<uint8_t> one;
            if (!mdDigest(env, chunkMd, &one)) return fail();
            chunkDigests.insert(chunkDigests.end(), one.begin(), one.end());
            pos += n;
        }
    }
    uint8_t topHeader[5] = {0x5a, 0, 0, 0, 0};
    put32(topHeader + 1, (uint32_t)chunks);
    if (!mdUpdate(env, topMd, topHeader, sizeof(topHeader)) ||
        !mdUpdate(env, topMd, chunkDigests.data(), chunkDigests.size()) ||
        !mdDigest(env, topMd, out)) return fail();
    env->PopLocalFrame(nullptr);
    return true;
}

static bool attrsClaimV3(const uint8_t *p, size_t n, bool *malformed) {
    Reader attrs{p, n, 0};
    while (!attrs.empty()) {
        Reader attr{nullptr, 0, 0};
        if (!attrs.sub(&attr)) { *malformed = true; return false; }
        uint32_t id = 0;
        if (!attr.u32(&id)) { *malformed = true; return false; }
        if (id == 0xbeeff00dU) {
            uint32_t version = 0;
            if (!attr.u32(&version) || !attr.empty()) { *malformed = true; return false; }
            if (version == 3U) return true;
        }
    }
    return false;
}

static bool verifyScheme(JNIEnv *env, const ApkLayout &layout,
                         const uint8_t *scheme, size_t schemeLen,
                         bool v3, int sdk, uint8_t certDigest[32], int *reason,
                         bool newerSchemePresent) {
    Reader root{scheme, schemeLen, 0};
    const uint8_t *signersBytes = nullptr; size_t signersLen = 0;
    if (!root.lp(&signersBytes, &signersLen) || !root.empty()) { *reason = 8; return false; }
    Reader signers{signersBytes, signersLen, 0};
    const uint8_t *selectedSigned = nullptr; size_t selectedSignedLen = 0;
    const uint8_t *selectedCert = nullptr; size_t selectedCertLen = 0;
    const uint8_t *selectedKey = nullptr; size_t selectedKeyLen = 0;
    const uint8_t *selectedSig = nullptr; size_t selectedSigLen = 0;
    Alg selectedAlg{};
    int selectedCount = 0;

    while (!signers.empty()) {
        Reader signer{nullptr, 0, 0};
        if (!signers.sub(&signer)) { *reason = 8; return false; }
        const uint8_t *signedData = nullptr, *signatures = nullptr, *publicKey = nullptr;
        size_t signedLen = 0, signaturesLen = 0, publicKeyLen = 0;
        if (!signer.lp(&signedData, &signedLen)) {
            *reason = 8; return false;
        }
        uint32_t minSdk = 0, maxSdk = 0;
        if (v3 && (!signer.u32(&minSdk) || !signer.u32(&maxSdk))) {
            *reason = 8; return false;
        }
        if (!signer.lp(&signatures, &signaturesLen) ||
            !signer.lp(&publicKey, &publicKeyLen) || !signer.empty()) {
            *reason = 8; return false;
        }
        Reader sd{signedData, signedLen, 0};
        const uint8_t *digestBytes = nullptr, *certBytes = nullptr, *attrs = nullptr;
        size_t digestLen = 0, certsLen = 0, attrsLen = 0;
        uint32_t signedMinSdk = 0, signedMaxSdk = 0;
        if (!sd.lp(&digestBytes, &digestLen) || !sd.lp(&certBytes, &certsLen)) {
            *reason = 8; return false;
        }
        if (v3 && (!sd.u32(&signedMinSdk) || !sd.u32(&signedMaxSdk))) {
            *reason = 8; return false;
        }
        if (!sd.lp(&attrs, &attrsLen) || !sd.empty()) { *reason = 8; return false; }
        if (v3 && (minSdk > maxSdk || signedMinSdk != minSdk ||
                    signedMaxSdk != maxSdk)) {
            *reason = 15; return false;
        }
        /* V3 may contain SDK-range signers. A signer outside the current
         * platform range is ignored; it must not reject an applicable signer. */
        if (v3 && ((uint32_t)sdk < minSdk || (uint32_t)sdk > maxSdk))
            continue;
        /* Key-rotation/proof-of-rotation attributes are deliberately not
         * accepted yet. This verifier therefore supports non-rotated v3 APKs
         * and fails closed for rotated APKs. */
        if (v3 && attrsLen != 0) {
            *reason = 15; return false;
        }
        if (!v3 && !newerSchemePresent) {
            bool malformedAttrs = false;
            if (attrsClaimV3(attrs, attrsLen, &malformedAttrs) || malformedAttrs) {
                *reason = 15; return false;
            }
        }

        Reader certList{certBytes, certsLen, 0};
        const uint8_t *firstCert = nullptr; size_t firstCertLen = 0;
        int certCount = 0;
        while (!certList.empty()) {
            const uint8_t *cert = nullptr; size_t certLen = 0;
            if (!certList.lp(&cert, &certLen)) { *reason = 8; return false; }
            if (certCount++ == 0) { firstCert = cert; firstCertLen = certLen; }
        }
        if (!firstCert || certCount == 0) { *reason = 8; return false; }

        std::vector<AlgRecord> digests, signaturesRecords;
        if (!parseAlgRecords(digestBytes, digestLen, &digests) ||
            !parseAlgRecords(signatures, signaturesLen, &signaturesRecords) ||
            digests.size() != signaturesRecords.size()) {
            *reason = 8; return false;
        }
        for (size_t i = 0; i < digests.size(); i++)
            if (digests[i].id != signaturesRecords[i].id) { *reason = 15; return false; }

        Alg best{}; const AlgRecord *bestSig = nullptr;
        for (const AlgRecord &record : signaturesRecords) {
            Alg candidate{};
            if (algorithm(record.id, &candidate) &&
                (!bestSig || candidate.rank > best.rank)) {
                best = candidate; bestSig = &record;
            }
        }
        if (!bestSig) { *reason = 15; return false; }
        const AlgRecord *bestDigest = nullptr;
        for (const AlgRecord &record : digests)
            if (record.id == best.id) { bestDigest = &record; break; }
        if (!bestDigest || (int)bestDigest->len != best.digestBytes) { *reason = 8; return false; }

        if (selectedCount++ != 0) { *reason = 15; return false; }
        selectedSigned = signedData; selectedSignedLen = signedLen;
        selectedCert = firstCert; selectedCertLen = firstCertLen;
        selectedKey = publicKey; selectedKeyLen = publicKeyLen;
        selectedSig = bestSig->data; selectedSigLen = bestSig->len;
        selectedAlg = best;
        if (!verifyJavaSignature(env, selectedAlg, selectedCert, selectedCertLen,
                                 selectedKey, selectedKeyLen, selectedSigned, selectedSignedLen,
                                 selectedSig, selectedSigLen, certDigest)) {
            *reason = 14; return false;
        }
        std::vector<uint8_t> actual;
        if (!computeContentDigest(env, layout, selectedAlg, &actual) ||
            actual.size() != bestDigest->len ||
            memcmp(actual.data(), bestDigest->data, actual.size()) != 0) {
            *reason = 16; return false;
        }
    }
    if (selectedCount != 1) { *reason = 15; return false; }
    return true;
}

} // namespace

bool vmpVerifyApkSignature(JNIEnv *env, jobject ctx, uint8_t certDigest[32],
                           bool *noSigBlock, int *reason) {
    *noSigBlock = false; *reason = 0;
    ApkLayout layout;
    if (!loadLayout(env, ctx, &layout, reason)) {
        *noSigBlock = (*reason == 3 || *reason == 5);
        return false;
    }
    const uint8_t *v3 = nullptr, *v2 = nullptr, *v31 = nullptr;
    size_t v3Len = 0, v2Len = 0, v31Len = 0;
    int v3Status = findPair(layout.signingBlock, V3_BLOCK_ID, &v3, &v3Len);
    int v2Status = findPair(layout.signingBlock, V2_BLOCK_ID, &v2, &v2Len);
    int v31Status = findPair(layout.signingBlock, V31_BLOCK_ID, &v31, &v31Len);
    if (v3Status < 0 || v2Status < 0 || v31Status < 0) {
        close(layout.fd); *reason = 6; return false;
    }
    bool hasV3 = v3Status == 1;
    bool hasV2 = v2Status == 1;
    bool hasV31 = v31Status == 1;
    if (hasV31 || (!hasV2 && !hasV3)) {
        close(layout.fd); *noSigBlock = !hasV31; *reason = hasV31 ? 15 : 7; return false;
    }
    int sdk = 0;
    if (!getSdkInt(env, &sdk)) {
        close(layout.fd); *reason = 10; return false;
    }
    bool ok = false;
    if (sdk >= 28 && hasV3)
        ok = verifyScheme(env, layout, v3, v3Len, true, sdk, certDigest, reason, hasV3);
    else
        ok = verifyScheme(env, layout, v2, v2Len, false, sdk, certDigest, reason, hasV3);
    close(layout.fd);
    return ok;
}
