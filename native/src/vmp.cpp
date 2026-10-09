#include <jni.h>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <ffi.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <mutex>
#include <new>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "miniz.h"
#include "vmp_file.h"
#include "vmp_sigblock.h"
#include "vmp_apk_verify.h"
#include "interpreter.h"

#include "vmp_log.h"
#include "vmp_obf.h"

static JavaVM *g_jvm = nullptr;

static inline void vmp_wipe(void *p, size_t n) {
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}
static uint8_t g_vmcKey[32];
static uint8_t g_insnKey[32];
static uint8_t g_authKey[32];
static bool g_insnKeyDerived = false;
static int g_certPinState = 0;
static uint8_t g_keySlot[112] = {
    0x5E, 0xA2, 0x17, 0xCB, 0x84, 0x39, 0xF1, 0x6D,
    0xB0, 0x25, 0x9E, 0x48, 0xDA, 0x73, 0x0C, 0xEF,
    0x3C, 0x91, 0x0A, 0x77, 0xE2, 0x5B, 0xC8, 0x16,
    0x4F, 0xDA, 0x23, 0x68, 0xB0, 0x05, 0x9E, 0x31,
    0x7A, 0xC4, 0x12, 0x8D, 0x46, 0xF3, 0x59, 0x0B,
    0x6E, 0xA1, 0x27, 0xD5, 0x38, 0x80, 0x1C, 0x64
};

static std::atomic<int> g_lazyFiles{0};

void vmpNoteLazyFile() {
    g_lazyFiles.fetch_add(1, std::memory_order_relaxed);
}

void vmpLazyFileReady() {
    if (g_lazyFiles.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        vmp_wipe(g_insnKey, sizeof(g_insnKey));
        LOGI("key: g_insnKey retired after last lazy insn decrypt");
    }
}

/** Owns one decoded VMP2 blob and its VmpFile, for the process lifetime. */
struct VmpFileInstance {
    uint8_t *data = nullptr;
    size_t size = 0;
    VmpFile *file = nullptr;
};

static std::vector<VmpFileInstance> g_vmpFiles;

static thread_local int g_interpDepth = 0;
static thread_local const VmMethod *g_interpInnermost = nullptr;
static std::atomic<bool> g_loggedSameMethodReentry{false};
static const int VMP_MAX_INTERP_DEPTH = 24;

bool vmpInterpEnter(void) {
    if (g_interpDepth >= VMP_MAX_INTERP_DEPTH) return false;
    ++g_interpDepth;
    return true;
}

void vmpInterpLeave(void) {
    if (g_interpDepth > 0) --g_interpDepth;
}

static std::atomic<bool> g_traceEnabled{false};
static int g_traceLines = 0;
static const int kMaxTraceLines = 40000;

struct ClosureData {
    VmpFile *file;
    uint32_t xKey;
    uint32_t eIdx;
};

static uint32_t vmpEncodeIdx(int v, int idx, uint32_t k) {
    switch (v) {
        case 0:  return ((uint32_t)(idx + 1)) ^ k;
        case 1:  return ((uint32_t)(idx + 2)) ^ k;
        case 2:  return ((uint32_t)idx ^ k) + 1u;
        default: return ((uint32_t)idx ^ k) + 2u;
    }
}
template <int V>
static inline int vmpDecodeIdx(uint32_t e, uint32_t k) {
    if (V < 2)
        return (int)((e ^ k) - (uint32_t)(1 + (V & 1)));
    return (int)(((e - (uint32_t)(1 + (V & 1))) ^ k));
}

static uint64_t g_cdSeed = 0;
static uint32_t vmpClosureMask(void) {
    if (!g_cdSeed)
        g_cdSeed = ((uint64_t)(uintptr_t)&g_cdSeed << 17)
                 ^ ((uint64_t)getpid() << 32)
                 ^ (uint64_t)time(nullptr) ^ 0x9E3779B97F4A7C15ull;
    g_cdSeed = g_cdSeed * 6364136223846793005ull + 1442695040888963407ull;
    return 0x10000000u | ((uint32_t)(g_cdSeed >> 35) & ~0x1Fu);
}


template <int V>
__attribute__((always_inline))
static inline void vmpHandlerCore(ffi_cif *cif, void *ret, void **args, void *userdata) {
    if (ret && cif && cif->rtype) memset(ret, 0, cif->rtype->size);
    ClosureData *cd = static_cast<ClosureData *>(userdata);
    if (!cd || !cd->file) {
        LOGE("vmp-closure: invalid userdata");
        return;
    }

    JNIEnv *env = nullptr;
    g_jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
    if (!env) {
        LOGE("vmp-closure: GetEnv failed");
        return;
    }

    const int methodIdx = vmpDecodeIdx<V>(cd->eIdx, cd->xKey);
    const VmMethod *method = cd->file->getMethod(methodIdx);
    if (!method) {
        LOGE("vmp-closure: bad method index %d", methodIdx);
        return;
    }

    jobject self = args[1] ? *(jobject *)args[1] : nullptr;
    const bool isStatic = (method->access & 0x8) != 0;

    const char *shorty = cd->file->getMethodShorty(method->method_id_idx);
    if (!shorty) {
        LOGE("vmp-closure: no shorty for method %d", method->method_id_idx);
        return;
    }

    int paramCount = (int)strlen(shorty) - 1;
    if (paramCount < 0) paramCount = 0;
    std::vector<jvalue> jargs((size_t)paramCount);

    auto fillSlot = [&](int i, void **slot) {
        switch (shorty[i + 1]) {
            case 'Z': jargs[i].z = *(jboolean *)slot[0]; break;
            case 'B': jargs[i].b = *(jbyte *)slot[0]; break;
            case 'S': jargs[i].s = *(jshort *)slot[0]; break;
            case 'C': jargs[i].c = *(jchar *)slot[0]; break;
            case 'I': jargs[i].i = *(jint *)slot[0]; break;
            case 'J': jargs[i].j = *(jlong *)slot[0]; break;
            case 'F': jargs[i].f = *(jfloat *)slot[0]; break;
            case 'D': jargs[i].d = *(jdouble *)slot[0]; break;
            default:  jargs[i].l = *(jobject *)slot[0]; break;
        }
    };
    if (V & 1) {
        int lim = paramCount;
        const int avail = (int)cif->nargs - 2;
        if (lim > avail) lim = avail;
        for (int i = lim; i-- > 0; )
            fillSlot(i, args + 2 + i);
    } else {
        int argOffset = 2;
        for (int i = 0; i < paramCount; i++) {
            if (argOffset >= (int)cif->nargs) break;
            fillSlot(i, args + argOffset);
            argOffset++;
        }
    }

    if (g_interpInnermost == method && !g_loggedSameMethodReentry) {
        g_loggedSameMethodReentry = true;
        const char *rc = cd->file->getMethodClass(method->method_id_idx);
        const char *rn = cd->file->getMethodName(method->method_id_idx);
        LOGE("VMP: re-entrant virtualized frame (depth %d): %s.%s",
             g_interpDepth, rc ? rc : "?", rn ? rn : "?");
    }
    if (g_interpDepth >= VMP_MAX_INTERP_DEPTH) {
        const char *dc = cd->file->getMethodClass(method->method_id_idx);
        const char *dn = cd->file->getMethodName(method->method_id_idx);
        LOGE("VMP: interpreter nesting depth %d exceeded at %s.%s",
             g_interpDepth, dc ? dc : "?", dn ? dn : "?");
        jclass soe = env->FindClass("java/lang/StackOverflowError");
        if (soe) {
            env->ThrowNew(soe, "Internal error: execution limit exceeded");
            env->DeleteLocalRef(soe);
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        if (ret && cif && cif->rtype)
            vmp_wipe(ret, (size_t)cif->rtype->size);
        return;
    }

    const VmMethod *prevInnermost = g_interpInnermost;
    g_interpInnermost = method;
    ++g_interpDepth;
    bool traced = g_traceEnabled && g_traceLines < kMaxTraceLines;
    if (traced) {
        g_traceLines += 2;
        const char *tc = cd->file->getMethodClass(method->method_id_idx);
        const char *tn = cd->file->getMethodName(method->method_id_idx);
        LOGI("VM> d%d %s.%s", g_interpDepth, tc ? tc : "?", tn ? tn : "?");
    }
    VmResult result = vmInterpret(env, self, cd->file, method, jargs.data(), isStatic);
    if (traced) {
        const char *tc2 = cd->file->getMethodClass(method->method_id_idx);
        const char *tn2 = cd->file->getMethodName(method->method_id_idx);
        LOGI("VM< d%d %s.%s exc=%d", g_interpDepth, tc2 ? tc2 : "?", tn2 ? tn2 : "?",
             result.exception ? 1 : 0);
    }
    --g_interpDepth;
    g_interpInnermost = prevInnermost;

    switch (shorty[0]) {
        case 'V': break;
        case 'Z': *(jboolean *)ret = result.value.z; break;
        case 'B': *(jbyte *)ret = result.value.b; break;
        case 'S': *(jshort *)ret = result.value.s; break;
        case 'C': *(jchar *)ret = result.value.c; break;
        case 'I': *(jint *)ret = result.value.i; break;
        case 'J': *(jlong *)ret = result.value.j; break;
        case 'F': *(jfloat *)ret = result.value.f; break;
        case 'D': *(jdouble *)ret = result.value.d; break;
        default: *(jobject *)ret = result.value.l; break;
    }

}

static void vmpHandlerV0(ffi_cif *c, void *r, void **a, void *u) { vmpHandlerCore<0>(c, r, a, u); }
static void vmpHandlerV1(ffi_cif *c, void *r, void **a, void *u) { vmpHandlerCore<1>(c, r, a, u); }
static void vmpHandlerV2(ffi_cif *c, void *r, void **a, void *u) { vmpHandlerCore<2>(c, r, a, u); }
static void vmpHandlerV3(ffi_cif *c, void *r, void **a, void *u) { vmpHandlerCore<3>(c, r, a, u); }

static void (*const kHandlerVariants[4])(ffi_cif *, void *, void **, void *) = {
    vmpHandlerV0, vmpHandlerV1, vmpHandlerV2, vmpHandlerV3,
};

static ffi_type *shortyToFfiType(char type) {
    switch (type) {
        case 'V': return &ffi_type_void;
        case 'Z': return &ffi_type_uint8;
        case 'B': return &ffi_type_sint8;
        case 'S': return &ffi_type_sint16;
        case 'C': return &ffi_type_uint16;
        case 'I': return &ffi_type_sint32;
        case 'J': return &ffi_type_sint64;
        case 'F': return &ffi_type_float;
        case 'D': return &ffi_type_double;
        default:  return &ffi_type_pointer;
    }
}

/**
 * ffi_prep_cif stores (never copies) the arg_types pointer, so the array must
 * outlive the cif: it, the cif, the closure and the userdata are all
 * intentionally process-lifetime allocations.
 */
#ifndef VMP_RELEASE_QUIET
static void vmpLogPendingClassLoad(
        JNIEnv *env, const char *phase, const char *jniName) {
    if (!env->ExceptionCheck()) return;
    jthrowable thrown = env->ExceptionOccurred();
    env->ExceptionClear();
    std::string type = "JavaThrowable";
    std::string message;
    if (thrown) {
        jclass thrownClass = env->GetObjectClass(thrown);
        jclass metaClass = thrownClass ? env->GetObjectClass(thrownClass) : nullptr;
        jmethodID getName = metaClass
            ? env->GetMethodID(metaClass, "getName", "()Ljava/lang/String;")
            : nullptr;
        jmethodID getMessage = thrownClass
            ? env->GetMethodID(thrownClass, "getMessage", "()Ljava/lang/String;")
            : nullptr;
        jstring typeName = (getName && thrownClass)
            ? (jstring)env->CallObjectMethod(thrownClass, getName) : nullptr;
        jstring text = (getMessage && thrownClass)
            ? (jstring)env->CallObjectMethod(thrown, getMessage) : nullptr;
        if (typeName) {
            const char *p = env->GetStringUTFChars(typeName, nullptr);
            if (p) { type = p; env->ReleaseStringUTFChars(typeName, p); }
            env->DeleteLocalRef(typeName);
        }
        if (text) {
            const char *p = env->GetStringUTFChars(text, nullptr);
            if (p) { message = p; env->ReleaseStringUTFChars(text, p); }
            env->DeleteLocalRef(text);
        }
        if (metaClass) env->DeleteLocalRef(metaClass);
        if (thrownClass) env->DeleteLocalRef(thrownClass);
        env->DeleteLocalRef(thrown);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    LOGE("vmp-reg: %s failed for %s (%s%s%s)", phase, jniName,
         type.c_str(), message.empty() ? "" : ": ", message.c_str());
}
#endif

static jclass vmpFindAppClass(JNIEnv *env, jobject context, const char *jniName) {
    jclass direct = env->FindClass(jniName);
    if (direct) return direct;
#ifndef VMP_RELEASE_QUIET
    vmpLogPendingClassLoad(env, "FindClass", jniName);
#endif
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!context) return nullptr;

    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getLoader = ctxClass
        ? env->GetMethodID(ctxClass, "getClassLoader", "()Ljava/lang/ClassLoader;")
        : nullptr;
    jobject loader = (getLoader && ctxClass)
        ? env->CallObjectMethod(context, getLoader) : nullptr;
    if (!loader || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (ctxClass) env->DeleteLocalRef(ctxClass);
        return nullptr;
    }

    jclass loaderClass = env->FindClass("java/lang/ClassLoader");
    jmethodID loadClass = loaderClass
        ? env->GetMethodID(loaderClass, "loadClass",
                          "(Ljava/lang/String;)Ljava/lang/Class;")
        : nullptr;
    std::string dotted(jniName);
    for (char &c : dotted) if (c == '/') c = '.';
    jstring name = env->NewStringUTF(dotted.c_str());
    jobject found = (loadClass && name)
        ? env->CallObjectMethod(loader, loadClass, name) : nullptr;
    const bool failed = env->ExceptionCheck() != 0;
#ifndef VMP_RELEASE_QUIET
    if (failed) vmpLogPendingClassLoad(env, "ClassLoader.loadClass", jniName);
#endif
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (name) env->DeleteLocalRef(name);
    if (loaderClass) env->DeleteLocalRef(loaderClass);
    env->DeleteLocalRef(loader);
    if (ctxClass) env->DeleteLocalRef(ctxClass);
    return failed ? nullptr : (jclass)found;
}

static bool registerMethodWithFfi(
        JNIEnv *env, VmpFile *file, int methodIdx, jobject context) {
    const VmMethod *method = file->getMethod(methodIdx);
    if (!method) return false;

    const char *shorty = file->getMethodShorty(method->method_id_idx);
    if (!shorty) return false;

    int paramCount = (int)strlen(shorty) - 1;
    if (paramCount < 0) paramCount = 0;

    int ffiArgCount = 2 + paramCount;
    ffi_type **argTypes = new ffi_type*[ffiArgCount];
    argTypes[0] = &ffi_type_pointer;
    argTypes[1] = &ffi_type_pointer;

    for (int i = 0; i < paramCount; i++) {
        argTypes[2 + i] = shortyToFfiType(shorty[i + 1]);
    }

    ffi_type *retType = shortyToFfiType(shorty[0]);

    ffi_cif *cif = new ffi_cif;
    if (ffi_prep_cif(cif, FFI_DEFAULT_ABI, ffiArgCount, retType, argTypes) != FFI_OK) {
        LOGE("ffi_prep_cif failed for method %d", methodIdx);
        delete[] argTypes;
        delete cif;
        return false;
    }

    void *code = nullptr;
    ffi_closure *closure = (ffi_closure *)ffi_closure_alloc(sizeof(ffi_closure), &code);
    if (!closure) {
        LOGE("ffi_closure_alloc failed for method %d", methodIdx);
        delete[] argTypes;
        delete cif;
        return false;
    }

    const uint32_t mk = vmpClosureMask();
    const int variant = (int)((g_cdSeed >> 13) & 3u);
    ClosureData *cd = new ClosureData{file, mk,
                                      vmpEncodeIdx(variant, methodIdx, mk)};

    if (ffi_prep_closure_loc(closure, cif, kHandlerVariants[variant], cd, code) != FFI_OK) {
        LOGE("ffi_prep_closure_loc failed for method %d", methodIdx);
        ffi_closure_free(closure);
        delete[] argTypes;
        delete cif;
        delete cd;
        return false;
    }

    const char *className = file->getMethodClass(method->method_id_idx);
    const char *methodName = file->getMethodName(method->method_id_idx);
    if (!className || !methodName) {
        LOGE("vmp-reg: null class or name for method %d", methodIdx);
        ffi_closure_free(closure);
        delete[] argTypes;
        delete cif;
        delete cd;
        return false;
    }

    const char *sigC = file->getMethodSig(method->method_id_idx);
    if (!sigC) {
        LOGE("vmp-reg: no signature for method %d", methodIdx);
        ffi_closure_free(closure);
        delete[] argTypes;
        delete cif;
        delete cd;
        return false;
    }
    std::string sig = sigC;

    const size_t clsLen = strlen(className);
    if (clsLen < 3 || className[0] != 'L' || className[clsLen - 1] != ';') {
        LOGE("vmp-reg: bad class descriptor for method %d", methodIdx);
        ffi_closure_free(closure);
        delete[] argTypes;
        delete cif;
        delete cd;
        return false;
    }
    std::string jniName(className + 1, clsLen - 2);

    JNINativeMethod nativeMethod;
    nativeMethod.name = const_cast<char *>(methodName);
    nativeMethod.signature = const_cast<char *>(sig.c_str());
    nativeMethod.fnPtr = code;

    jclass clazz = vmpFindAppClass(env, context, jniName.c_str());
    if (!clazz) {
#ifdef VMP_RELEASE_QUIET
        LOGE("vmp-reg: class lookup failed");
#else
        LOGE("vmp-reg: class lookup failed for %s.%s%s",
             jniName.c_str(), methodName, sig.c_str());
#endif
        ffi_closure_free(closure);
        delete[] argTypes;
        delete cif;
        delete cd;
        return false;
    }

    jint ret = env->RegisterNatives(clazz, &nativeMethod, 1);
    env->DeleteLocalRef(clazz);

    if (ret != JNI_OK) {
#ifdef VMP_RELEASE_QUIET
        LOGE("vmp-reg: RegisterNatives failed");
#else
        LOGE("RegisterNatives failed for %s.%s (%s)", jniName.c_str(), methodName, sig.c_str());
#endif
        ffi_closure_free(closure);
        delete[] argTypes;
        delete cif;
        delete cd;
        return false;
    }

    LOGI("Registered native: %s.%s%s", jniName.c_str(), methodName, sig.c_str());
    return true;
}

#define VMP_LOADER_CLASS_TEMPLATE "com/error/vm"
#define VMP_INITVM_SIG \
    "(Landroid/content/res/AssetManager;IZLandroid/content/Context;)V"

static const char kLoaderClass[] = VMP_LOADER_CLASS_TEMPLATE;
static void vmpInitVMImpl(JNIEnv *env, jclass clazz, jobject assetManager,
                          jint dexIndex, jboolean debug, jobject ctx);

static constexpr char kNameInitVM[] = {
    'i'^0x5C,'n'^0x5C,'i'^0x5C,'t'^0x5C,'V'^0x5C,'M'^0x5C,'\0'^0x5C
};
static constexpr char kSigInitVM[] = {
    '('^0x5C,
    'L'^0x5C,'a'^0x5C,'n'^0x5C,'d'^0x5C,'r'^0x5C,'o'^0x5C,'i'^0x5C,'d'^0x5C,'/'^0x5C,
    'c'^0x5C,'o'^0x5C,'n'^0x5C,'t'^0x5C,'e'^0x5C,'n'^0x5C,'t'^0x5C,'/'^0x5C,
    'r'^0x5C,'e'^0x5C,'s'^0x5C,'/'^0x5C,'A'^0x5C,'s'^0x5C,'s'^0x5C,'e'^0x5C,'t'^0x5C,
    'M'^0x5C,'a'^0x5C,'n'^0x5C,'a'^0x5C,'g'^0x5C,'e'^0x5C,'r'^0x5C,';'^0x5C,
    'I'^0x5C,'Z'^0x5C,
    'L'^0x5C,'a'^0x5C,'n'^0x5C,'d'^0x5C,'r'^0x5C,'o'^0x5C,'i'^0x5C,'d'^0x5C,'/'^0x5C,
    'c'^0x5C,'o'^0x5C,'n'^0x5C,'t'^0x5C,'e'^0x5C,'n'^0x5C,'t'^0x5C,'/'^0x5C,
    'C'^0x5C,'o'^0x5C,'n'^0x5C,'t'^0x5C,'e'^0x5C,'x'^0x5C,'t'^0x5C,';'^0x5C,
    ')'^0x5C,'V'^0x5C,'\0'^0x5C
};

static_assert(sizeof(kSigInitVM) == sizeof(VMP_INITVM_SIG),
              "kSigInitVM no longer matches VMP_INITVM_SIG byte for byte");

__attribute__((optnone))
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    for (int i = 0; i < 32; i++) {
        uint32_t enc = g_keySlot[48 + i];
        uint32_t bc  = g_keySlot[16 + i];
        uint32_t key = vmp_xor(enc, bc);                 /* == enc ^ bc */
        if (vmp_never0((uint32_t)i)) key = vmp_xor(key, 0u);  /* guarded no-op */
        g_vmcKey[i] = (uint8_t)key;
    }
    vmp_wipe(g_keySlot + 16, 64);

    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
#ifdef VMP_RELEASE_QUIET
        LOGE("vmp-init: E_ENV");
#else
        LOGE("JNI_OnLoad: GetEnv failed");
#endif
        return JNI_ERR;
    }
    jclass loader = env->FindClass(kLoaderClass);
    if (!loader) {
#ifdef VMP_RELEASE_QUIET
        LOGE("vmp-init: E_LOADER");
#else
        LOGE("JNI_OnLoad: loader class not found - stale .so or packer mismatch?");
#endif
        if (env->ExceptionCheck()) env->ExceptionClear();
        return JNI_ERR;
    }
    char nameBuf[sizeof(kNameInitVM)], sigBuf[sizeof(kSigInitVM)];
    for (size_t i = 0; i < sizeof(kNameInitVM); i++)
        nameBuf[i] = (char)(kNameInitVM[i] ^ 0x5C);
    for (size_t i = 0; i < sizeof(kSigInitVM); i++)
        sigBuf[i] = (char)(kSigInitVM[i] ^ 0x5C);
    JNINativeMethod loaderNative;
    loaderNative.name = nameBuf;
    loaderNative.signature = sigBuf;
    loaderNative.fnPtr = (void *) vmpInitVMImpl;
    if (env->RegisterNatives(loader, &loaderNative, 1) != JNI_OK) {
#ifdef VMP_RELEASE_QUIET
        LOGE("vmp-init: E_BIND");
#else
        LOGE("JNI_OnLoad: loader native bind failed");
#endif
        if (env->ExceptionCheck()) env->ExceptionClear();
        return JNI_ERR;
    }
    env->DeleteLocalRef(loader);
    LOGI("JNI_OnLoad: VMP loaded");
    return JNI_VERSION_1_6;
}


static const uint32_t VMC_CONTAINER_MAGIC = 0x43504D56u;
static const uint32_t VMC_CONTAINER_VERSION = 4;
static const uint32_t VMC_TOC_ENTRY_SIZE = 48;

static inline uint32_t vmp_rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint32_t vmp_rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

static void vmp_chacha20_block(const uint8_t key[32], uint32_t counter,
                               const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t s[16], x[16];
    s[0] = 0x61707865u; s[1] = 0x3320646eu; s[2] = 0x79622d32u; s[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++)
        s[4 + i] = (uint32_t)key[4*i] | ((uint32_t)key[4*i+1] << 8) |
                   ((uint32_t)key[4*i+2] << 16) | ((uint32_t)key[4*i+3] << 24);
    s[12] = counter;
    for (int i = 0; i < 3; i++)
        s[13 + i] = (uint32_t)nonce[4*i] | ((uint32_t)nonce[4*i+1] << 8) |
                    ((uint32_t)nonce[4*i+2] << 16) | ((uint32_t)nonce[4*i+3] << 24);
    for (int i = 0; i < 16; i++) x[i] = s[i];

#define VMP_QR(a, b, c, d)                            \
    x[a] += x[b]; x[d] = vmp_rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = vmp_rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = vmp_rotl32(x[d] ^ x[a], 8);  \
    x[c] += x[d]; x[b] = vmp_rotl32(x[b] ^ x[c], 7);

    for (int r = 0; r < 10; r++) {
        VMP_QR(0, 4, 8, 12);  VMP_QR(1, 5, 9, 13);
        VMP_QR(2, 6, 10, 14); VMP_QR(3, 7, 11, 15);
        VMP_QR(0, 5, 10, 15); VMP_QR(1, 6, 11, 12);
        VMP_QR(2, 7, 8, 13);  VMP_QR(3, 4, 9, 14);
    }
#undef VMP_QR

    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        out[4*i]   = (uint8_t)v;
        out[4*i+1] = (uint8_t)(v >> 8);
        out[4*i+2] = (uint8_t)(v >> 16);
        out[4*i+3] = (uint8_t)(v >> 24);
    }
}

static void vmpChaChaTransform(const uint8_t *src, uint8_t *dst, size_t len,
                               uint32_t blobIndex) {
    uint8_t nonce[12] = {0};
    nonce[0] = (uint8_t)blobIndex;
    nonce[1] = (uint8_t)(blobIndex >> 8);
    nonce[2] = (uint8_t)(blobIndex >> 16);
    nonce[3] = (uint8_t)(blobIndex >> 24);
    uint8_t block[64];
    size_t off = 0;
    uint32_t counter = 0;
    while (off < len) {
        vmp_chacha20_block(g_vmcKey, counter, nonce, block);
        size_t n = (len - off < 64) ? (len - off) : 64;
        for (size_t j = 0; j < n; j++)
            dst[off + j] = (uint8_t)vmp_xor(src[off + j], block[j]);
        off += n;
        counter++;
    }
}

void vmp_decryptInsns(uint8_t *p, size_t len, uint32_t insns_off) {
    uint8_t nonce[12] = {0x44,0x41,0x54,0x41, 0,0,0,0, 0,0,0,0};
    nonce[4] = (uint8_t)insns_off;
    nonce[5] = (uint8_t)(insns_off >> 8);
    nonce[6] = (uint8_t)(insns_off >> 16);
    nonce[7] = (uint8_t)(insns_off >> 24);
    uint8_t block[64];
    uint32_t counter = 0;
    for (size_t off = 0; off < len; off += 64, counter++) {
        vmp_chacha20_block(g_insnKey, counter, nonce, block);
        size_t n = (len - off < 64) ? (len - off) : 64;
        for (size_t j = 0; j < n; j++)
            p[off + j] = (uint8_t)vmp_xor(p[off + j], block[j]);
    }
}

static bool vmpChaChaSelfTest(void) {
    uint8_t key[32], nonce[12] = {0,0,0,9,0,0,0,0x4a,0,0,0,0}, out[64];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    vmp_chacha20_block(key, 1, nonce, out);
    static const uint8_t exp[64] = {
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
        0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
        0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e};
    for (int i = 0; i < 64; i++) if (out[i] != exp[i]) return false;
    return true;
}

static void vmpDeriveInsnKey(void) {
    uint8_t block[64];
    const uint8_t kdfNonce[12] = {0x56, 0x4D, 0x50, 0x4B, 0x30, 0x4B,
                                  0x44, 0x46, 0x49, 0x4E, 0x53, 0x4E};
    vmp_chacha20_block(g_vmcKey, 0x2E17A3C1u, kdfNonce, block);
    memcpy(g_insnKey, block, 32);
    vmp_wipe(block, sizeof(block));
}

static void vmpDeriveAuthKey(void) {
    uint8_t block[64];
    const uint8_t authNonce[12] = {0x56, 0x4D, 0x50, 0x43, 0x30, 0x4B,
                                   0x41, 0x55, 0x54, 0x48, 0x56, 0x34};
    vmp_chacha20_block(g_vmcKey, 0x2E17A3C2u, authNonce, block);
    memcpy(g_authKey, block, 32);
    vmp_wipe(block, sizeof(block));
}

static void vmpDeriveAllKeys(void) {
    if (g_insnKeyDerived) return;
    vmpDeriveInsnKey();
    vmpDeriveAuthKey();
    g_insnKeyDerived = true;
}

static uint32_t vmp_crc32(const uint8_t *p, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/**
 * Authenticate, decrypt + inflate one blob, verify its CRC. The HMAC over the
 * bound metadata and ciphertext runs before decryption, so a tag mismatch or
 * failed self-test prevents decryption, inflation, and parsing; CRC is checked
 * after inflation.
 * *outPlain is caller-owned on success, nothing is allocated on failure.
 */
static const uint32_t VMP_MAX_BLOB_BYTES = 512u * 1024u * 1024u;

static bool vmpDecodeBlob(const uint8_t *src, uint32_t compSize,
                          uint32_t plainSize, uint32_t plainCrc,
                          const uint8_t *tag,
                          uint32_t blobIndex, uint8_t **outPlain) {
    if (!src || !tag || !outPlain || compSize == 0 || plainSize == 0 ||
        compSize > VMP_MAX_BLOB_BYTES || plainSize > VMP_MAX_BLOB_BYTES)
        return false;
    if ((uint64_t)compSize + 16u > SIZE_MAX)
        return false;
    uint8_t *auth = new (std::nothrow) uint8_t[(size_t)compSize + 16u];
    if (!auth) return false;
    auth[0] = (uint8_t)blobIndex; auth[1] = (uint8_t)(blobIndex >> 8);
    auth[2] = (uint8_t)(blobIndex >> 16); auth[3] = (uint8_t)(blobIndex >> 24);
    auth[4] = (uint8_t)compSize; auth[5] = (uint8_t)(compSize >> 8);
    auth[6] = (uint8_t)(compSize >> 16); auth[7] = (uint8_t)(compSize >> 24);
    auth[8] = (uint8_t)plainSize; auth[9] = (uint8_t)(plainSize >> 8);
    auth[10] = (uint8_t)(plainSize >> 16); auth[11] = (uint8_t)(plainSize >> 24);
    auth[12] = (uint8_t)plainCrc; auth[13] = (uint8_t)(plainCrc >> 8);
    auth[14] = (uint8_t)(plainCrc >> 16); auth[15] = (uint8_t)(plainCrc >> 24);
    memcpy(auth + 16, src, compSize);
    uint8_t gotTag[32];
    const bool macOk = vmpHmacSha256(g_authKey, sizeof(g_authKey),
                                     auth, (size_t)compSize + 16u, gotTag);
    vmp_wipe(auth, (size_t)compSize + 16u);
    delete[] auth;
    if (!macOk) return false;
    volatile int tagDiff = 0;
    for (int i = 0; i < 32; i++)
        tagDiff |= (int)(gotTag[i] ^ tag[i]);
    vmp_wipe(gotTag, sizeof(gotTag));
    if (tagDiff != 0) {
        LOGDIAG("vmp-init: blob %u authentication failed (tampered container)",
                blobIndex);
        return false;
    }

    if ((uint64_t)plainSize > 4096ull + 1032ull * (uint64_t)compSize) {
        LOGE("vmp-init: blob %u implausible plainSize %u for compSize %u",
             blobIndex, plainSize, compSize);
        return false;
    }

    uint8_t *deflated = new (std::nothrow) uint8_t[compSize];
    if (!deflated) return false;
    vmpChaChaTransform(src, deflated, compSize, blobIndex);

    uint8_t *plain = new (std::nothrow) uint8_t[plainSize];
    if (!plain) { delete[] deflated; return false; }

    tinfl_decompressor infl = {};
    size_t inBytes  = (size_t)compSize;
    size_t outBytes = (size_t)plainSize;
    tinfl_status st = tinfl_decompress(
        &infl, deflated, &inBytes,
        plain, plain, &outBytes,
        TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    delete[] deflated;

    if (st != TINFL_STATUS_DONE || outBytes != (size_t)plainSize) {
        delete[] plain;
        return false;
    }
    if (vmp_crc32(plain, (size_t)plainSize) != plainCrc) {
        delete[] plain;
        return false;
    }
    *outPlain = plain;
    return true;
}

/**
 * Registers one in-memory VMP2 blob's methods via ffi closures, copying the blob
 * into a VmpFileInstance-owned buffer. Returns false only when the blob cannot be
 * parsed at all - not conflated with "0 methods", which a valid empty container gives.
 */
static bool registerVmcFromMemory(JNIEnv *env, const uint8_t *data, size_t size,
                                  const std::string &label, jobject context,
                                  int *outRegistered, int *outTotal) {
    *outRegistered = 0;
    *outTotal = 0;

    LOGI("initVM: loading %s", label.c_str());

    if (!data || size == 0) {
        LOGE("vmp-init: empty VMC %s", label.c_str());
        return false;
    }

    uint8_t *buf = new uint8_t[size];
    memcpy(buf, data, size);

    VmpFileInstance vfi;
    vfi.data = buf;
    vfi.size = size;
    vfi.file = new VmpFile();

    if (!vfi.file->open(buf, size)) {
        LOGE("vmp-init: container open failed for %s", label.c_str());
        delete vfi.file;
        delete[] buf;
        return false;
    }

    LOGI("initVM: VMP2 opened with %d virtualized methods", vfi.file->getMethodCount());

    int methodCount = vfi.file->getMethodCount();
    int registered = 0;
    for (int i = 0; i < methodCount; i++) {
        if (registerMethodWithFfi(env, vfi.file, i, context)) {
            registered++;
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    LOGI("initVM: registered %d/%d methods via ffi", registered, methodCount);

    *outRegistered = registered;
    *outTotal = methodCount;
    if (registered != methodCount) {
        LOGE("vmp-init: only registered %d/%d methods for %s",
             registered, methodCount, label.c_str());
        return false;
    }

    g_vmpFiles.push_back(vfi);
    return true;
}



#define VMP_ANTIDBG_HARD 0

static volatile bool g_instrumented = false;

static long vmpReadProc(const char *path, char *buf, size_t cap) {
    if (cap == 0) return -1;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = 0;
    while (n + 1 < cap) {
        const ssize_t r = read(fd, buf + n, cap - n - 1);
        if (r <= 0) break;
        n += (size_t)r;
    }
    buf[n] = 0;
    close(fd);
    return (long)n;
}

static int vmpReadTracerPid(void) {
    char buf[1024];
    if (vmpReadProc("/proc/self/status", buf, sizeof buf) < 0) return -1;
    const char *p = strstr(buf, "TracerPid:");
    if (!p) return -1;
    return atoi(p + 10);
}

static bool mapsHasAgentTokens(const char *s) {
    return strstr(s, "frida") || strstr(s, "gum-js") ||
           strstr(s, "libgadget") || strstr(s, "linjector") ||
           strstr(s, "gdbserver") || strstr(s, "lldb-server") ||
           strstr(s, "libsubstitute");
}

static bool vmpMapsHasAgent(void) {
    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const size_t overlap = 64;
    char buf[4096];
    size_t carry = 0;
    bool hit = false;
    for (;;) {
        const ssize_t r = read(fd, buf + carry, sizeof buf - carry - 1);
        if (r <= 0) break;
        buf[carry + (size_t)r] = 0;
        if (mapsHasAgentTokens(buf)) { hit = true; break; }
        carry = (size_t)r;
        if (carry > overlap) {
            memmove(buf, buf + carry - overlap, overlap);
            carry = overlap;
        }
    }
    close(fd);
    return hit;
}

static int vmpThreadNameHits(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    int hits = 0;
    struct dirent *e;
    while ((e = readdir(d)) != nullptr && hits < 2) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[128];
        if (snprintf(path, sizeof path, "/proc/self/task/%s/comm", e->d_name)
                >= (int)sizeof path)
            continue;
        char name[64];
        if (vmpReadProc(path, name, sizeof name) < 0) continue;
        if (strstr(name, "gum-js") || strstr(name, "gmain") ||
            strstr(name, "frida"))
            hits++;
    }
    closedir(d);
    return hits;
}

static int vmpAntiDbgScore(void) {
    int score = 0;
    if (vmpReadTracerPid() > 0) score += 2;
    if (vmpMapsHasAgent()) score += 2;
    score += vmpThreadNameHits();
    return score;
}

static void vmpAntiDbgAct(void) {
    g_instrumented = true;
    g_traceEnabled = false;
    vmpSetInterpDebug(false);
    LOGDIAG("antidbg: instrumentation event - trace degraded, process marked");
#if VMP_ANTIDBG_HARD
    LOGE("antidbg: HARD policy - aborting");
    abort();
#endif
}

static void *vmpAntiDbgLoop(void *unused) {
    (void)unused;
    unsigned seed = (unsigned)time(nullptr) ^ (unsigned)getpid();
    bool armed = true;
    for (;;) {
        seed = seed * 1103515245u + 12345u;
        struct timespec ts;
        ts.tv_sec = armed ? 4 + (long)((seed >> 16) % 5u)
                          : 20 + (long)((seed >> 11) % 21u);
        ts.tv_nsec = 0;
        nanosleep(&ts, nullptr);
        if (vmpAntiDbgScore() >= 2) {
            if (armed) {
                vmpAntiDbgAct();
                armed = false;
            }
        } else {
            armed = true;
        }
    }
    return nullptr;
}

static void vmpAntiDbgStart(void) {
    if (vmpAntiDbgScore() >= 2) {
        vmpAntiDbgAct();
        return;
    }
    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, vmpAntiDbgLoop, nullptr) != 0)
        LOGDIAG("antidbg: probe thread failed to start (errno=%d)", errno);
    pthread_attr_destroy(&attr);
}

static bool vmpReadSignerCertDigest(JNIEnv *env, jobject ctx, uint8_t out[32]) {
    if (!ctx || env->PushLocalFrame(48) != 0) return false;
    bool ok = false;
    do {
        jclass ctxCls = env->GetObjectClass(ctx);
        if (!ctxCls) break;
        jmethodID mGetPkg = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
        jmethodID mGetPM  = env->GetMethodID(ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
        if (!mGetPkg || !mGetPM) { if (env->ExceptionCheck()) env->ExceptionClear(); break; }
        jstring pkg = (jstring)env->CallObjectMethod(ctx, mGetPkg);
        jobject pm = pkg ? env->CallObjectMethod(ctx, mGetPM) : nullptr;
        if (!pkg || !pm || env->ExceptionCheck()) { env->ExceptionClear(); break; }

        jclass pmCls = env->GetObjectClass(pm);
        jmethodID mGetPi = pmCls ? env->GetMethodID(pmCls, "getPackageInfo",
                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;") : nullptr;
        if (!mGetPi) { if (env->ExceptionCheck()) env->ExceptionClear(); break; }
        jobject pi = env->CallObjectMethod(pm, mGetPi, pkg, 0x00000040 /* GET_SIGNATURES */);
        if (!pi || env->ExceptionCheck()) { env->ExceptionClear(); break; }

        jclass piCls = env->GetObjectClass(pi);
        jfieldID fSigs = piCls ? env->GetFieldID(piCls, "signatures", "[Landroid/content/pm/Signature;") : nullptr;
        jobjectArray sigs = fSigs ? (jobjectArray)env->GetObjectField(pi, fSigs) : nullptr;
        if (!sigs) { if (env->ExceptionCheck()) env->ExceptionClear(); break; }
        if (env->GetArrayLength(sigs) < 1) break;
        jobject sig0 = env->GetObjectArrayElement(sigs, 0);
        jclass sigCls = sig0 ? env->GetObjectClass(sig0) : nullptr;
        jmethodID mToBytes = sigCls ? env->GetMethodID(sigCls, "toByteArray", "()[B") : nullptr;
        jbyteArray certDer = mToBytes ? (jbyteArray)env->CallObjectMethod(sig0, mToBytes) : nullptr;
        if (!certDer || env->ExceptionCheck()) { env->ExceptionClear(); break; }

        jclass mdCls = env->FindClass("java/security/MessageDigest");
        if (!mdCls) { env->ExceptionClear(); break; }
        jmethodID mInst = env->GetStaticMethodID(mdCls, "getInstance",
                "(Ljava/lang/String;)Ljava/security/MessageDigest;");
        jmethodID mUpd = env->GetMethodID(mdCls, "update", "([B)V");
        jmethodID mDig = env->GetMethodID(mdCls, "digest", "()[B");
        jstring alg = env->NewStringUTF("SHA-256");
        jobject md = (mInst && alg) ? env->CallStaticObjectMethod(mdCls, mInst, alg) : nullptr;
        if (!md || !mUpd || !mDig || env->ExceptionCheck()) { env->ExceptionClear(); break; }
        env->CallVoidMethod(md, mUpd, certDer);
        jbyteArray dig = env->ExceptionCheck() ? nullptr
                         : (jbyteArray)env->CallObjectMethod(md, mDig);
        if (!dig || env->ExceptionCheck()) { env->ExceptionClear(); break; }
        if (env->GetArrayLength(dig) != 32) break;
        env->GetByteArrayRegion(dig, 0, 32, (jbyte *)out);
        ok = !env->ExceptionCheck();
    } while (false);
    if (!ok) env->ExceptionClear();
    env->PopLocalFrame(nullptr);
    return ok;
}

static bool vmpCheckCertPin(JNIEnv *env, jobject ctx) {
    if (g_certPinState != 0) return g_certPinState == 1;
    bool unset = true;
    for (int i = 0; i < 32; i++)
        if (g_keySlot[80 + i]) { unset = false; break; }

    /* Always verify the APK signature first, even for an unpinned template.
     * A zero pin disables identity binding, not APK-content integrity. */
    uint8_t digF[32] = {0};
    bool noSigBlock = false;
    int fileReason = -1;
    bool gotFile = vmpVerifyApkSignature(env, ctx, digF, &noSigBlock, &fileReason);
    LOGDIAG("vmp-init: APK signature check (verified=%d noSigBlock=%d r=%d)",
            gotFile ? 1 : 0, noSigBlock ? 1 : 0, fileReason);
    if (!gotFile) {
        /* Keep verification failures out of release logcat. The Java-side
         * exception remains deliberately generic; debug builds retain the
         * reason for diagnosis without giving release observers an oracle. */
        LOGDIAG("vmp-init: APK signature verification failed (reason=%d)", fileReason);
        vmp_wipe(digF, sizeof(digF));
        vmp_wipe(g_keySlot + 80, 32);
        g_certPinState = 2;
        return false;
    }

    if (unset) {
        vmp_wipe(digF, sizeof(digF));
        vmp_wipe(g_keySlot + 80, 32);
        vmpDeriveAllKeys();
        g_certPinState = 1;
        return true;
    }

    int diffF = 0;
    for (int i = 0; i < 32; i++)
        diffF |= (int)(digF[i] ^ g_keySlot[80 + i]);
    vmp_wipe(g_keySlot + 80, 32);
    if (diffF != 0) {
        vmp_wipe(digF, sizeof(digF));
        LOGDIAG("vmp-init: verified signer certificate does not match the pin");
        g_certPinState = 2;
        return false;
    }
    for (int i = 0; i < 32; i++) g_vmcKey[i] ^= digF[i];
    vmp_wipe(digF, sizeof(digF));
    vmpDeriveAllKeys();
    g_certPinState = 1;
    return true;
}

static void vmpThrowInitError(JNIEnv *env) {
    if (!env) return;
    jclass ex = env->FindClass("java/lang/RuntimeException");
    if (ex) {
        env->ThrowNew(ex, "Unable to initialize context");
        env->DeleteLocalRef(ex);
    }
}

static void vmpInitVMImpl(JNIEnv *env, jclass /*clazz*/,
                          jobject assetManager, jint dexIndex, jboolean debug,
                          jobject ctx) {
    static std::mutex initMutex;
    static bool initDone = false;
    static bool initRejected = false;
    std::lock_guard<std::mutex> initLock(initMutex);
    if (initDone) {
        LOGI("initVM: already initialized, skipping");
        return;
    }
    if (initRejected) {
        vmpThrowInitError(env);
        return;
    }

    g_traceEnabled = debug;
    vmpSetInterpDebug(debug);
    if (!vmpCheckCertPin(env, ctx)) {
        initRejected = true;
        vmpThrowInitError(env);
        return;
    }

    AAssetManager *mgr = AAssetManager_fromJava(env, assetManager);
    if (!mgr) {
        LOGE("vmp-init: AAssetManager_fromJava failed");
        initRejected = true;
        vmpThrowInitError(env);
        return;
    }

    LOGI("initVM: start (dexIndex=%d debug=%d)", dexIndex, debug ? 1 : 0);
    if (g_traceEnabled && !vmpChaChaSelfTest())
        LOGE("VMP: ChaCha20 self-test FAILED - native keystream diverged from RFC 8439");
    int totalRegistered = 0;
    int totalMethods = 0;

    AAsset *asset = AAssetManager_open(mgr, "VMC.payload", AASSET_MODE_BUFFER);
    if (!asset) {
        LOGE("vmp-init: container asset not found");
        initRejected = true;
        vmpThrowInitError(env);
        return;
    }

    off_t assetSize = AAsset_getLength(asset);
    const void *assetData = AAsset_getBuffer(asset);
    if (!assetData || assetSize < 12) {
        LOGE("vmp-init: empty container asset");
        AAsset_close(asset);
        initRejected = true;
        vmpThrowInitError(env);
        return;
    }

    const uint8_t *bytes = (const uint8_t *)assetData;
    size_t size = (size_t)assetSize;
    uint32_t magic = vmp_rd_u32(bytes);

    if (magic == VMC_CONTAINER_MAGIC) {
        uint32_t version = vmp_rd_u32(bytes + 4);
        uint32_t count = vmp_rd_u32(bytes + 8);
        if (version != VMC_CONTAINER_VERSION || count == 0 ||
            count > (size - 12u) / (size_t)VMC_TOC_ENTRY_SIZE) {
            LOGE("vmp-init: bad container (version=%u count=%u size=%zu)",
                 version, count, size);
            AAsset_close(asset);
            initRejected = true;
            vmpThrowInitError(env);
            return;
        }
        LOGI("initVM: VMC container v%u with %u blob(s)", version, count);
        for (uint32_t i = 0; i < count; i++) {
            const uint8_t *e = bytes + 12 + (size_t)i * VMC_TOC_ENTRY_SIZE;
            uint32_t off       = vmp_rd_u32(e);
            uint32_t compSize  = vmp_rd_u32(e + 4);
            uint32_t plainSize = vmp_rd_u32(e + 8);
            uint32_t plainCrc  = vmp_rd_u32(e + 12);
            if ((size_t)off > size || (size_t)compSize > size - (size_t)off) {
                LOGE("vmp-init: blob %u out of range (off=%u comp=%u)", i, off, compSize);
                AAsset_close(asset);
                initRejected = true;
                vmpThrowInitError(env);
                return;
            }
            uint8_t *plain = nullptr;
            if (!vmpDecodeBlob(bytes + off, compSize, plainSize, plainCrc,
                               e + 16, i, &plain)) {
                LOGE("vmp-init: blob %u failed to decode", i);
                AAsset_close(asset);
                initRejected = true;
                vmpThrowInitError(env);
                return;
            }
            std::string label = "vmp blob " + std::to_string(i);
            int registered = 0;
            int methods = 0;
            const bool opened = registerVmcFromMemory(env, plain, plainSize, label,
                                                      ctx, &registered, &methods);
            delete[] plain;
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (!opened) {
                LOGE("vmp-init: blob %u unusable - refusing to start", i);
                AAsset_close(asset);
                initRejected = true;
                vmpThrowInitError(env);
                return;
            }
            totalRegistered += registered;
            totalMethods += methods;
        }
    } else {
        LOGE("vmp-init: unknown magic 0x%08x", magic);
        AAsset_close(asset);
        initRejected = true;
        vmpThrowInitError(env);
        return;
    }

    vmp_wipe(g_vmcKey, sizeof(g_vmcKey));
    vmp_wipe(g_authKey, sizeof(g_authKey));
    if (g_lazyFiles.load(std::memory_order_relaxed) == 0) {
        vmp_wipe(g_insnKey, sizeof(g_insnKey));
        LOGI("initVM: no lazy decryption pending - keys retired");
    }

    AAsset_close(asset);
    LOGI("initVM: done - registered %d/%d methods across all VMC files",
         totalRegistered, totalMethods);
    initDone = true;

    vmpAntiDbgStart();
}

