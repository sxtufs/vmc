#include "interpreter.h"

#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <mutex>
#include <atomic>
#include <vector>
#include <iterator>

#include "vmp_log.h"
#include "interpreter_jni.h"

typedef uint64_t Reg;

namespace {

#ifdef VMP_RELEASE_QUIET
inline uint16_t fetch16(const uint16_t *insns, int pc) { return insns[pc]; }
#else
static thread_local const uint16_t *g_insnReadBase = nullptr;
static thread_local const uint16_t *g_insnReadEnd = nullptr;
static thread_local bool g_insnReadPast = false;

class InsnReadScope {
public:
    InsnReadScope(const uint16_t *base, size_t units)
        : savedBase_(g_insnReadBase), savedEnd_(g_insnReadEnd),
          savedPast_(g_insnReadPast) {
        g_insnReadBase = base;
        g_insnReadEnd = base + units;
        g_insnReadPast = false;
    }
    ~InsnReadScope() {
        g_insnReadBase = savedBase_;
        g_insnReadEnd = savedEnd_;
        g_insnReadPast = savedPast_;
    }
    InsnReadScope(const InsnReadScope &) = delete;
    InsnReadScope &operator=(const InsnReadScope &) = delete;

private:
    const uint16_t *savedBase_;
    const uint16_t *savedEnd_;
    bool savedPast_;
};

inline uint16_t fetch16(const uint16_t *insns, int pc) {
    if (insns == g_insnReadBase &&
        (pc < 0 || (size_t)pc >= (size_t)(g_insnReadEnd - g_insnReadBase))) {
        g_insnReadPast = true;
        return 0xffff;
    }
    return insns[pc];
}
#endif

inline int32_t vI(const Reg *v, int r) { return (int32_t)(uint32_t)v[r]; }
inline int64_t vJ(const Reg *v, int r) { return (int64_t)v[r]; }
inline float vF(const Reg *v, int r) { float f; uint32_t lo = (uint32_t)v[r]; memcpy(&f, &lo, 4); return f; }
inline double vD(const Reg *v, int r) { double d; memcpy(&d, &v[r], 8); return d; }
inline jobject vL(const Reg *v, int r) { return (jobject)(uintptr_t)(v[r] & ~(Reg)(1ULL << 63)); }
inline bool regIsObj(const Reg *v, int r) { return (v[r] & (Reg)(1ULL << 63)) != 0; }

inline void wI(Reg *v, int r, int32_t x) { v[r] = (Reg)(uint32_t)x; }
inline void wJ(Reg *v, int r, int64_t x) { v[r] = (Reg)x; }
inline void wF(Reg *v, int r, float f) { uint32_t lo; memcpy(&lo, &f, 4); v[r] = (Reg)lo; }
inline void wD(Reg *v, int r, double d) { memcpy(&v[r], &d, 8); }
inline void wL(Reg *v, int r, jobject o) { v[r] = ((Reg)(uintptr_t)o) | (Reg)(1ULL << 63); }

/* Java integer arithmetic wraps at the register width. Do not express these
 * operations as signed C++ arithmetic: overflow is undefined behavior and the
 * optimizer may legally change the result. */
inline int32_t wrapAdd32(int32_t a, int32_t b) {
    return (int32_t)((uint32_t)a + (uint32_t)b);
}
inline int32_t wrapSub32(int32_t a, int32_t b) {
    return (int32_t)((uint32_t)a - (uint32_t)b);
}
inline int32_t wrapMul32(int32_t a, int32_t b) {
    return (int32_t)((uint32_t)a * (uint32_t)b);
}
inline int32_t wrapNeg32(int32_t a) {
    return (int32_t)(0u - (uint32_t)a);
}
inline int64_t wrapAdd64(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a + (uint64_t)b);
}
inline int64_t wrapSub64(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a - (uint64_t)b);
}
inline int64_t wrapMul64(int64_t a, int64_t b) {
    return (int64_t)((uint64_t)a * (uint64_t)b);
}
inline int64_t wrapNeg64(int64_t a) {
    return (int64_t)(0ull - (uint64_t)a);
}

/* Dalvik integer division/remainder define the signed overflow pair instead
 * of exposing C++ signed-division undefined behavior. The callers check b==0
 * and route that case through failArith(); these helpers handle only the
 * non-zero divisor case. */
inline int32_t dalvikDiv32(int32_t a, int32_t b) {
    if (a == INT32_MIN && b == -1) return INT32_MIN;
    return a / b;
}
inline int32_t dalvikRem32(int32_t a, int32_t b) {
    if (a == INT32_MIN && b == -1) return 0;
    return a % b;
}
inline int64_t dalvikDiv64(int64_t a, int64_t b) {
    if (a == INT64_MIN && b == -1) return INT64_MIN;
    return a / b;
}
inline int64_t dalvikRem64(int64_t a, int64_t b) {
    if (a == INT64_MIN && b == -1) return 0;
    return a % b;
}

/* Dalvik float/double-to-integer conversions truncate toward zero, map NaN to
 * zero, and saturate infinities/out-of-range values. Range checks precede the
 * C++ casts so no undefined or implementation-dependent conversion occurs. */
inline int32_t dalvikFpToInt(double x) {
    if (isnan(x)) return 0;
    if (x >= 0x1p31) return INT32_MAX;
    if (x <= -0x1p31) return INT32_MIN;
    return (int32_t)x;
}
inline int64_t dalvikFpToLong(double x) {
    if (isnan(x)) return 0;
    if (x >= 0x1p63) return INT64_MAX;
    if (x <= -0x1p63) return INT64_MIN;
    return (int64_t)x;
}


enum { INVOKE_VIRTUAL = 0, INVOKE_SUPER, INVOKE_DIRECT, INVOKE_STATIC, INVOKE_INTERFACE };


static std::mutex g_logRefsMutex;
static std::atomic<bool> g_logRefsReady{false};
static jclass g_logClass = nullptr;
static jclass g_stringClass = nullptr;
static jmethodID g_substringMid = nullptr;

static bool ensureLogRefs(JNIEnv *env) {
    if (g_logRefsReady.load(std::memory_order_acquire)) return true;
    std::lock_guard<std::mutex> lk(g_logRefsMutex);
    if (g_logRefsReady.load(std::memory_order_relaxed)) return true;
    if (!g_logClass) {
        jclass local = env->FindClass("android/util/Log");
        if (!local) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGE("vmp-guard: FindClass(android/util/Log) failed");
            return false;
        }
        g_logClass = (jclass)env->NewGlobalRef(local);
        env->DeleteLocalRef(local);
        if (!g_logClass) {
            LOGE("vmp-guard: NewGlobalRef(Log) returned null");
            return false;
        }
    }
    if (!g_stringClass) {
        jclass local = env->FindClass("java/lang/String");
        if (!local) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGE("vmp-guard: FindClass(java/lang/String) failed");
            return false;
        }
        g_stringClass = (jclass)env->NewGlobalRef(local);
        env->DeleteLocalRef(local);
        if (!g_stringClass) {
            LOGE("vmp-guard: NewGlobalRef(String) returned null");
            return false;
        }
    }
    if (!g_substringMid) {
        g_substringMid = env->GetMethodID(g_stringClass, "substring",
                                          "(II)Ljava/lang/String;");
        if (!g_substringMid) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGE("vmp-guard: GetMethodID(substring) failed");
            return false;
        }
    }
    g_logRefsReady.store(true, std::memory_order_release);
    return true;
}

static std::atomic<bool> g_loggedClassMismatch{false};
static std::atomic<bool> g_loggedNonStringMsg{false};
static std::atomic<bool> g_loggedUnchunked{false};
static std::atomic<bool> g_loggedGuardReached{false};
static std::atomic<bool> g_loggedGuardClaimed{false};

static std::atomic<int> g_loggedNullResult{0};
static std::atomic<int> g_nullVirtualResultCount{0};
static std::atomic<int> g_interfaceTraceCount{0};


static const int kArgCheckBudgetDebug = 1000000;
static const int kArgCheckBudgetRelease = 20000;
static const int kReadCheckBudgetDebug = 10000000;
static const int kReadCheckBudgetRelease = 200000;

static std::atomic<int> g_argCheckBudget{kArgCheckBudgetRelease};
static std::atomic<int> g_readCheckBudget{kReadCheckBudgetRelease};
static std::atomic<unsigned> g_readCheckTick{0};
static const unsigned kReadCheckSampleEvery = 64;
static std::atomic<unsigned> g_argCheckTick{0};
static const unsigned kArgCheckSampleEvery = 32;
static std::atomic<bool> g_logged35cWordMismatch{false};
static std::atomic<bool> g_argCheckExhaustedLogged{false};
static std::atomic<bool> g_readCheckSamplingLogged{false};

static bool argCheckEnabled() {
    if (g_argCheckBudget.load(std::memory_order_relaxed) > 0) {
        g_argCheckBudget.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }
    if (!g_argCheckExhaustedLogged.exchange(true, std::memory_order_relaxed)) {
        LOGI("argcheck: per-argument budget of %d exhausted - now sampling 1 in "
             "%u (write-side and field checks unchanged)",
             kArgCheckBudgetRelease, kArgCheckSampleEvery);
    }
    return (g_argCheckTick.fetch_add(1, std::memory_order_relaxed)
            % kArgCheckSampleEvery) == 0u;
}

static bool readCheckEnabled() {
    if (g_readCheckBudget.load(std::memory_order_relaxed) > 0) {
        g_readCheckBudget.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }
    if (!g_readCheckSamplingLogged.exchange(true, std::memory_order_relaxed))
        LOGI("argcheck: read-side budget of %d exhausted - now sampling 1 in "
             "%u (write-side checks remain permanent)",
             kReadCheckBudgetRelease, kReadCheckSampleEvery);
    return (g_readCheckTick.fetch_add(1, std::memory_order_relaxed)
            % kReadCheckSampleEvery) == 0u;
}

static const int kDescMax = 256;
static const int kDescCacheN = 48;

static std::mutex g_diagMutex;
static jclass g_descClass[kDescCacheN];
static char g_descKey[kDescCacheN][kDescMax];
static int g_descN = 0;

static jmethodID g_classGetNameMid = nullptr;

static bool ensureClassNameMid(JNIEnv *env) {
    std::lock_guard<std::mutex> lk(g_diagMutex);
    if (g_classGetNameMid) return true;
    jclass c = env->FindClass("java/lang/Class");
    if (!c) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    g_classGetNameMid = env->GetMethodID(c, "getName", "()Ljava/lang/String;");
    env->DeleteLocalRef(c);
    if (!g_classGetNameMid) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    return true;
}

/** Descriptor ("Landroid/animation/TimeInterpolator;", "[I", ...) -> jclass,
 *  with a tiny global-ref cache. Returns nullptr when unresolvable (the
 *  check is skipped for that argument - never a false positive). */
static jclass classOfDesc(JNIEnv *env, const char *desc, int len) {
    std::lock_guard<std::mutex> lk(g_diagMutex);
    if (len <= 1 || len >= kDescMax) {
        static std::atomic<bool> tooLongLogged{false};
        if (!tooLongLogged.exchange(true, std::memory_order_relaxed))
            LOGDIAG("classOfDesc: descriptor of %d chars exceeds the %d-char "
                    "slot - type checks skipped for it (and any longer name)",
                    len, kDescMax - 1);
        return nullptr;
    }
    char key[kDescMax];
    memcpy(key, desc, (size_t)len);
    key[len] = 0;
    for (int i = 0; i < g_descN; i++)
        if (strcmp(g_descKey[i], key) == 0) return g_descClass[i];
    char name[kDescMax];
    if (key[0] == 'L' && key[len - 1] == ';') {
        memcpy(name, key + 1, (size_t)len - 2);
        name[len - 2] = 0;
    } else {
        memcpy(name, key, (size_t)len + 1);
    }
    jclass local = env->FindClass(name);
    if (!local) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    jclass g = (jclass)env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    if (!g) return nullptr;
    if (g_descN < kDescCacheN) {
        strncpy(g_descKey[g_descN], key, sizeof(g_descKey[g_descN]) - 1);
        g_descKey[g_descN][sizeof(g_descKey[g_descN]) - 1] = 0;
        g_descClass[g_descN] = g;
        g_descN++;
    } else {
        static std::atomic<bool> fullLogged{false};
        if (!fullLogged.exchange(true, std::memory_order_relaxed))
            LOGDIAG("classOfDesc: %d-entry descriptor cache full - type checks "
                    "skipped for all further classes", kDescCacheN);
        env->DeleteGlobalRef(g);
        return nullptr;
    }
    return g;
}

/** VmMethod for a method-id index, or nullptr when it is not virtualized.
 *  Tracer-only: dispatch is by name, so this cannot change semantics. */
static const VmMethod *methodByIdx(VmpFile *file, int methodIdIdx) {
    return file ? file->getMethodByMethodId(methodIdIdx) : nullptr;
}

/**
 * True for android.util.Log's print methods. Detection is by class IDENTITY plus
 * method name, never by the VMC shorty, so a corrupt shorty cannot bypass the
 * guard; (String,String,Throwable) forms match and re-emit as 2-arg.
 */
static bool isLogPrintCall(JNIEnv *env, VmpFile *file, int methodIdIdx,
                           jclass clazz, const jvalue *args,
                           int msgIdx, int nparams) {
    if (!clazz || !file) return false;
    if (!ensureLogRefs(env)) return false;

    if (env->IsSameObject(clazz, g_logClass) != JNI_TRUE) {
        if (!g_loggedClassMismatch) {
            g_loggedClassMismatch = true;
            LOGDIAG("logguard: Log-shaped call resolved to a class that is NOT android/util/Log");
        }
        return false;
    }

    const char *name = file->getMethodName(methodIdIdx);
    bool isPrint = name &&
        (strcmp(name, "v") == 0 || strcmp(name, "d") == 0 ||
         strcmp(name, "i") == 0 || strcmp(name, "w") == 0 ||
         strcmp(name, "e") == 0 || strcmp(name, "wtf") == 0 ||
         strcmp(name, "println") == 0);
    if (!isPrint) return false;

    if (msgIdx < 0 || msgIdx >= nparams) return false;
    jstring msg = (jstring)args[msgIdx].l;
    if (msg && env->IsInstanceOf(msg, g_stringClass) != JNI_TRUE) {
        if (!g_loggedNonStringMsg) {
            g_loggedNonStringMsg = true;
            LOGDIAG("logguard: message argument is not a String");
        }
        return false;
    }
    return true;
}

/**
 * Re-emits one Log print through clazz/mid in bounded chunks.
 *   (String tag, String msg)               -> tagIdx=0, msgIdx=1
 *   (int priority, String tag, String msg) -> tagIdx=1, msgIdx=2
 * Returns false only when the single-call path is safe; true when dispatched
 * (last result in *outInt, exceptions routed by the caller).
 */
static bool printChunkedLog(JNIEnv *env, jclass clazz, jmethodID mid,
                            const char *name, int nparams,
                            const jvalue *args, int tagIdx, int msgIdx,
                            jint *outInt) {
    static const int kMaxChunkChars = 800;
    static const int kMaxTagChars = 500;

    bool hasThrowable = (nparams == 3 && name && strcmp(name, "println") != 0);

    jstring msg = (jstring)args[msgIdx].l;
    jstring tag = (jstring)args[tagIdx].l;

    jsize msgLen = 0;
    if (msg) {
        msgLen = env->GetStringLength(msg);
        if (env->ExceptionCheck()) {
            LOGE("vmp-guard: GetStringLength(msg) threw");
            env->ExceptionClear();
            msg = nullptr;
            msgLen = 0;
        }
    }
    jsize tagLen = 0;
    if (tag) {
        tagLen = env->GetStringLength(tag);
        if (env->ExceptionCheck()) {
            LOGE("vmp-guard: GetStringLength(tag) threw");
            env->ExceptionClear();
            tag = nullptr;
            tagLen = 0;
        }
    }

    if (!hasThrowable && msgLen <= kMaxChunkChars && tagLen <= kMaxTagChars)
        return false;

    if (!ensureLogRefs(env)) {
        jclass rte = env->FindClass("java/lang/RuntimeException");
        if (rte) {
            env->ThrowNew(rte, "Internal error: log guard refs unavailable");
            env->DeleteLocalRef(rte);
        }
        return true;
    }

    jmethodID emitMid = mid;
    if (hasThrowable) {
        emitMid = env->GetStaticMethodID(clazz, name,
                                         "(Ljava/lang/String;Ljava/lang/String;)I");
        if (!emitMid) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            LOGE("vmp-guard: GetStaticMethodID(%s,String,String) failed", name);
            jclass rte = env->FindClass("java/lang/RuntimeException");
            if (rte) {
                env->ThrowNew(rte, "Internal error: cannot resolve 2-arg Log print");
                env->DeleteLocalRef(rte);
            }
            return true;
        }
    }

    jstring outTag = tag;
    if (tag && tagLen > kMaxTagChars) {
        jvalue sa[2];
        sa[0].i = 0; sa[1].i = kMaxTagChars;
        jstring capped = (jstring)env->CallObjectMethodA(tag, g_substringMid, sa);
        if (!capped || env->ExceptionCheck()) {
            LOGE("vmp-guard: tag cap failed (len=%d) - throwing", tagLen);
            if (env->ExceptionCheck()) env->ExceptionClear();
            jclass rte = env->FindClass("java/lang/RuntimeException");
            if (rte) {
                env->ThrowNew(rte, "Internal error: cannot chunk oversized Log tag");
                env->DeleteLocalRef(rte);
            }
            return true;
        }
        outTag = capped;
    }

    if (msgLen <= kMaxChunkChars) {
        jvalue callArgs[3];
        int callN = 0;
        if (nparams == 3 && !hasThrowable) callArgs[callN++] = args[0];
        callArgs[callN].l = outTag; callN++;
        callArgs[callN].l = msg; callN++;
        jint single = env->CallStaticIntMethodA(clazz, emitMid, callArgs);
        if (outInt) *outInt = single;
        return true;
    }

    static std::atomic<bool> loggedOnce{false};
    if (!loggedOnce.exchange(true, std::memory_order_relaxed))
        LOGI("oversized android.util.Log print: splitting into chunks");

    bool dispatched = false;
    jint lastResult = 0;
    int start = 0;
    while (start < msgLen) {
        int end = start + kMaxChunkChars;
        if (end > msgLen) end = msgLen;
        jvalue sa[2];
        sa[0].i = start; sa[1].i = end;
        jstring chunk = (jstring)env->CallObjectMethodA(msg, g_substringMid, sa);
        if (!chunk || env->ExceptionCheck()) {
            LOGE("vmp-guard: substring failed at %d/%d - throwing", start, msgLen);
            if (env->ExceptionCheck()) env->ExceptionClear();
            jclass rte = env->FindClass("java/lang/RuntimeException");
            if (rte) {
                env->ThrowNew(rte, "Internal error: cannot chunk oversized Log message");
                env->DeleteLocalRef(rte);
            }
            return true;
        }
        jvalue callArgs[3];
        int callN = 0;
        if (nparams == 3 && !hasThrowable) callArgs[callN++] = args[0];
        callArgs[callN].l = outTag; callN++;
        callArgs[callN].l = chunk;  callN++;
        lastResult = env->CallStaticIntMethodA(clazz, emitMid, callArgs);
        env->DeleteLocalRef(chunk);
        dispatched = true;
        if (env->ExceptionCheck()) break;
        start = end;
    }

    if (!dispatched) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (hasThrowable) {
            jclass rte = env->FindClass("java/lang/RuntimeException");
            if (rte) {
                env->ThrowNew(rte, "Internal error: cannot chunk oversized Log print");
                env->DeleteLocalRef(rte);
            }
            return true;
        }
        return false;
    }
    if (outInt) *outInt = lastResult;
    return true;
}

/**
 * Unified invoke. regs[] holds register numbers (receiver first for instance
 * calls); returns false if a Java exception is now pending.
 */
bool doInvoke(JNIEnv *env, VmpFile *file, const Reg *v, uint32_t methodIdIdx,
              int kind, const int *regs, int nregs, jvalue *out, int pc,
              const VmMethod *caller) {
    const char *shorty = file->getMethodShorty(methodIdIdx);
    if (!shorty) {
        LOGE("vm-invoke: no shorty for method %u", methodIdIdx);
        jclass ie = env->FindClass("java/lang/InternalError");
        if (ie) {
            env->ThrowNew(ie, "Internal error: cannot resolve invoked method shorty");
            env->DeleteLocalRef(ie);
        }
        return false;
    }
    int nparams = (int)strlen(shorty) - 1;
    if (nparams < 0) nparams = 0;
    bool isStatic = (kind == INVOKE_STATIC);
    const bool virtualDispatch =
        (kind == INVOKE_VIRTUAL || kind == INVOKE_INTERFACE);
    jobject receiver = nullptr;
    if (!isStatic) {
        if (nregs < 1) {
            LOGE("vm-invoke: no receiver register for method %u", methodIdIdx);
            jclass ie = env->FindClass("java/lang/InternalError");
            if (ie) {
                env->ThrowNew(ie, "Internal error: invoke with no receiver register");
                env->DeleteLocalRef(ie);
            }
            return false;
        }
        receiver = vL(v, regs[0]);
        if (caller && (regs[0] < 0 || regs[0] >= caller->regs)) {
            LOGE("vm-invoke: receiver reg v%d out of range (regs=%d) method %u pc=%d",
                 regs[0], caller->regs, methodIdIdx, pc);
            jclass ie = env->FindClass("java/lang/InternalError");
            if (ie) {
                env->ThrowNew(ie, "Internal error: invoke receiver register out of range");
                env->DeleteLocalRef(ie);
            }
            return false;
        }
        if (receiver == nullptr) {
            const char *nullCls = file->getMethodClass((int)methodIdIdx);
            const char *nullName = file->getMethodName((int)methodIdIdx);
            LOGE("vm-invoke: null receiver for method %u (kind=%d) %s.%s%s pc=%d reg[0]=%d prev=%p",
                 methodIdIdx, kind,
                 nullCls ? nullCls : "?",
                 nullName ? nullName : "?",
                 shorty ? shorty : "",
                 pc, nregs >= 1 ? regs[0] : -1,
                 (void*)(out ? out->l : nullptr));
            for (int di = 0; di < nregs && di < 8; di++) {
                LOGE("  arg[%d]=reg %d = 0x%llx", di, regs[di],
                     (unsigned long long)v[regs[di]]);
            }
            jclass npe = env->FindClass("java/lang/NullPointerException");
            if (npe) {
                env->ThrowNew(npe, "null receiver in invoke");
                env->DeleteLocalRef(npe);
            }
            return false;
        }
    }
    jmethodID mid = file->methodOf(env, (int)methodIdIdx, isStatic);
    if (!mid) {
        if (!env->ExceptionCheck()) {
            LOGE("vm-invoke: cannot resolve method %u", methodIdIdx);
            jclass ie = env->FindClass("java/lang/InternalError");
            if (ie) {
                env->ThrowNew(ie, "Internal error: cannot resolve invoked method");
                env->DeleteLocalRef(ie);
            }
        }
        return false;
    }
    jclass clazz = file->classOf(env, (int)methodIdIdx);
    if (!clazz) {
        if (!env->ExceptionCheck()) {
            LOGE("vm-invoke: cannot resolve class for method %u", methodIdIdx);
            jclass ie = env->FindClass("java/lang/InternalError");
            if (ie) {
                env->ThrowNew(ie, "Internal error: cannot resolve invoked method class");
                env->DeleteLocalRef(ie);
            }
        }
        return false;
    }

    if (nparams > 255) {
        LOGE("vm-invoke: shorty declares %d params for method %u (dex max 255)",
             nparams, methodIdIdx);
        jclass ie = env->FindClass("java/lang/InternalError");
        if (ie) {
            env->ThrowNew(ie, "Internal error: malformed method prototype");
            env->DeleteLocalRef(ie);
        }
        return false;
    }
    std::vector<jvalue> argBuf((size_t)(nparams > 0 ? nparams : 1));
    jvalue *args = argBuf.data();
    memset(args, 0, sizeof(jvalue) * (size_t)(nparams > 0 ? nparams : 1));
    for (int i = 0; i < nparams; i++) {
        int r = regs[i + (isStatic ? 0 : 1)];
        if (caller && (r < 0 || r >= caller->regs)) {
            LOGE("vm-arg register v%d out of range (regs=%d) param#%d method %u pc=%d",
                 r, caller->regs, i, methodIdIdx, pc);
            jclass ie = env->FindClass("java/lang/InternalError");
            if (ie) {
                env->ThrowNew(ie, "Internal error: invoke argument register out of range");
                env->DeleteLocalRef(ie);
            }
            return false;
        }
        char t = shorty[i + 1];
        switch (t) {
            case 'L': args[i].l = vL(v, r); break;
            case 'I': case 'Z': case 'B': case 'C': case 'S': args[i].i = vI(v, r); break;
            case 'J': args[i].j = vJ(v, r); break;
            case 'F': args[i].f = vF(v, r); break;
            case 'D': args[i].d = vD(v, r); break;
        }
    }
    char rt = shorty[0];
    memset(out, 0, sizeof(jvalue));

    if (!virtualDispatch) {
        const VmMethod *calleeVm = file->getMethodByMethodId((int)methodIdIdx);
        if (calleeVm != nullptr) {
            if (!vmpInterpEnter()) {
                jclass soe = env->FindClass("java/lang/StackOverflowError");
                if (soe) {
                    env->ThrowNew(soe, "Internal error: execution limit exceeded");
                    env->DeleteLocalRef(soe);
                } else if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                return false;
            }
            VmResult vr = vmInterpret(env, receiver, file, calleeVm, args, isStatic);
            vmpInterpLeave();
            *out = vr.value;
            return !hasPendingException(env);
        }
    }

    if (isStatic) {
        if (!g_loggedGuardReached) {
            g_loggedGuardReached = true;
            LOGI("logguard: static dispatch guard reached "
                 "(name=%s shorty=%s nparams=%d rt=%c)",
                 file->getMethodName((int)methodIdIdx),
                 shorty ? shorty : "(null)", nparams, rt);
        }
        const char *printName = file->getMethodName((int)methodIdIdx);
        int tagArgIdx = 0;
        int msgArgIdx = 1;
        if (printName && strcmp(printName, "println") == 0 && nparams == 3) {
            tagArgIdx = 1;
            msgArgIdx = 2;
        }
        bool logGuardClaimed = false;
        if (msgArgIdx < nparams &&
            isLogPrintCall(env, file, (int)methodIdIdx, clazz, args,
                           msgArgIdx, nparams)) {
            logGuardClaimed = true;
            if (!g_loggedGuardClaimed) {
                g_loggedGuardClaimed = true;
                LOGI("logguard: claiming Log print (name=%s nparams=%d)",
                     printName ? printName : "(null)", nparams);
            }
            jint logResult = 0;
            if (printChunkedLog(env, clazz, mid, printName, nparams, args,
                                tagArgIdx, msgArgIdx, &logResult)) {
                out->i = logResult;
                return !hasPendingException(env);
            }
        }
        if (!logGuardClaimed && !g_loggedUnchunked &&
            env->IsSameObject(clazz, g_logClass) == JNI_TRUE) {
            g_loggedUnchunked = true;
            LOGDIAG("logguard: UNCHUNKED android/util/Log dispatch: "
                 "isLogPrintCall=false (name=%s nparams=%d shorty=%s)",
                 file->getMethodName((int)methodIdIdx), nparams,
                 shorty ? shorty : "(null)");
        }
    }

    if (argCheckEnabled()) {
        const char *sig = file->getMethodSig((int)methodIdIdx);
        if (sig && sig[0] == '(') {
            const char *p = sig + 1;
            int ai = 0;
            while (*p && *p != ')' && ai < nparams) {
                const char *start = p;
                bool isObj = false;
                if (*p == '[') { while (*p == '[') p++; isObj = true; }
                if (*p == 'L') { while (*p && *p != ';') p++; if (*p == ';') p++; isObj = true; }
                else if (*p) p++;
                int len = (int)(p - start);
                if (isObj && args[ai].l && len < 72) {
                    jclass dc = classOfDesc(env, start, len);
                    if (dc && env->IsInstanceOf(args[ai].l, dc) != JNI_TRUE) {
                        const char *tc = file->getMethodClass((int)methodIdIdx);
                        const char *tn = file->getMethodName((int)methodIdIdx);
                        const char *cc = caller ? file->getMethodClass(caller->method_id_idx) : nullptr;
                        const char *cn = caller ? file->getMethodName(caller->method_id_idx) : nullptr;
                        LOGE("vm-arg type mismatch: param#%d expects %.*s",
                             ai, len, start);
                        LOGE("  callee: %s.%s%s",
                             tc ? tc : "?", tn ? tn : "?", sig);
                        LOGE("  caller: %s.%s call_pc=%d reg=v%d arg=0x%llx",
                             cc ? cc : "(external)", cn ? cn : "?", pc,
                             regs[ai + (isStatic ? 0 : 1)],
                             (unsigned long long)args[ai].l);
                        if (ensureClassNameMid(env)) {
                            jclass oc = env->GetObjectClass(args[ai].l);
                            if (oc) {
                                jstring nm = (jstring)env->CallObjectMethod(oc, g_classGetNameMid);
                                if (nm && !env->ExceptionCheck()) {
                                    const char *u = env->GetStringUTFChars(nm, nullptr);
                                    LOGE("  actual argument class: %s", u ? u : "?");
                                    if (u) env->ReleaseStringUTFChars(nm, u);
                                }
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                env->DeleteLocalRef(nm);
                                env->DeleteLocalRef(oc);
                            } else if (env->ExceptionCheck()) {
                                env->ExceptionClear();
                            }
                        }
#ifndef VMP_RELEASE_QUIET
                        if (caller) {
                            const uint16_t *cins = file->getInsns(caller);
                            char chex[600];
                            size_t co = 0;
                            int cn_cnt = caller->insns_size < 64 ? caller->insns_size : 64;
                            for (int i = 0; cins && i < cn_cnt && co + 5 < sizeof(chex); i++) {
                                int cw = snprintf(chex + co, sizeof(chex) - co, "%04x",
                                                  (unsigned)fetch16(cins, i));
                                if (cw > 0) co += (size_t)cw;
                            }
                            chex[co] = 0;
                            LOGE("  caller bytecode (%d units, first 64): %s",
                                 caller->insns_size, chex);
                        }
#endif
                        jclass icce = env->FindClass("java/lang/IncompatibleClassChangeError");
                        if (icce) {
                            env->ThrowNew(icce, "Internal error: argument type mismatch at call site");
                            env->DeleteLocalRef(icce);
                        }
                        return false;
                    }
                }
                ai++;
            }
        }
    }

    if (isStatic) {
        switch (rt) {
            case 'V': env->CallStaticVoidMethodA(clazz, mid, args); break;
            case 'L': out->l = env->CallStaticObjectMethodA(clazz, mid, args); break;
            case 'I': out->i = env->CallStaticIntMethodA(clazz, mid, args); break;
            case 'Z': out->i = env->CallStaticBooleanMethodA(clazz, mid, args); break;
            case 'B': out->i = env->CallStaticByteMethodA(clazz, mid, args); break;
            case 'C': out->i = env->CallStaticCharMethodA(clazz, mid, args); break;
            case 'S': out->i = env->CallStaticShortMethodA(clazz, mid, args); break;
            case 'J': out->j = env->CallStaticLongMethodA(clazz, mid, args); break;
            case 'F': out->f = env->CallStaticFloatMethodA(clazz, mid, args); break;
            case 'D': out->d = env->CallStaticDoubleMethodA(clazz, mid, args); break;
        }
    } else if (kind == INVOKE_VIRTUAL || kind == INVOKE_INTERFACE) {
        switch (rt) {
            case 'V': env->CallVoidMethodA(receiver, mid, args); break;
            case 'L': out->l = env->CallObjectMethodA(receiver, mid, args); break;
            case 'I': out->i = env->CallIntMethodA(receiver, mid, args); break;
            case 'Z': out->i = env->CallBooleanMethodA(receiver, mid, args); break;
            case 'B': out->i = env->CallByteMethodA(receiver, mid, args); break;
            case 'C': out->i = env->CallCharMethodA(receiver, mid, args); break;
            case 'S': out->i = env->CallShortMethodA(receiver, mid, args); break;
            case 'J': out->j = env->CallLongMethodA(receiver, mid, args); break;
            case 'F': out->f = env->CallFloatMethodA(receiver, mid, args); break;
            case 'D': out->d = env->CallDoubleMethodA(receiver, mid, args); break;
        }
    } else {
        switch (rt) {
            case 'V': env->CallNonvirtualVoidMethodA(receiver, clazz, mid, args); break;
            case 'L': out->l = env->CallNonvirtualObjectMethodA(receiver, clazz, mid, args); break;
            case 'I': out->i = env->CallNonvirtualIntMethodA(receiver, clazz, mid, args); break;
            case 'Z': out->i = env->CallNonvirtualBooleanMethodA(receiver, clazz, mid, args); break;
            case 'B': out->i = env->CallNonvirtualByteMethodA(receiver, clazz, mid, args); break;
            case 'C': out->i = env->CallNonvirtualCharMethodA(receiver, clazz, mid, args); break;
            case 'S': out->i = env->CallNonvirtualShortMethodA(receiver, clazz, mid, args); break;
            case 'J': out->j = env->CallNonvirtualLongMethodA(receiver, clazz, mid, args); break;
            case 'F': out->f = env->CallNonvirtualFloatMethodA(receiver, clazz, mid, args); break;
            case 'D': out->d = env->CallNonvirtualDoubleMethodA(receiver, clazz, mid, args); break;
        }
    }
    if (g_vmpDebug && rt == 'L' && g_interfaceTraceCount < 40) {
        const char *cc0 = file->getMethodClass((int)methodIdIdx);
        const char *cn0 = file->getMethodName((int)methodIdIdx);
        bool isSuspect = cc0 && (strstr(cc0, "compose/runtime/j") != nullptr);
        if (isSuspect) {
            g_interfaceTraceCount++;
            const char *cls0 = "?";
            if (out->l) {
                if (ensureClassNameMid(env)) {
                    jclass oc0 = env->GetObjectClass(out->l);
                    if (oc0) {
                        jstring nm0 = (jstring)env->CallObjectMethod(oc0, g_classGetNameMid);
                        if (nm0 && !env->ExceptionCheck()) {
                            const char *u0 = env->GetStringUTFChars(nm0, nullptr);
                            cls0 = u0 ? u0 : "?";
                            LOGI("iface-dispatch: kind=%d %s.%s -> %s (ptr=0x%llx)",
                                 kind, cc0 ? cc0 : "?", cn0 ? cn0 : "?", cls0,
                                 (unsigned long long)(uintptr_t)out->l);
                            env->ReleaseStringUTFChars(nm0, u0);
                        }
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        env->DeleteLocalRef(nm0);
                        env->DeleteLocalRef(oc0);
                    } else if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                    }
                }
            } else {
                LOGI("iface-dispatch: kind=%d %s.%s -> null",
                     kind, cc0 ? cc0 : "?", cn0 ? cn0 : "?");
            }
        }
    }
    if (g_vmpDebug && rt == 'L' && out->l == nullptr && g_nullVirtualResultCount < 8 &&
        methodByIdx(file, (int)methodIdIdx) != nullptr) {
        g_nullVirtualResultCount++;
        const VmMethod *cm = methodByIdx(file, (int)methodIdIdx);
        const char *nc = file->getMethodClass(cm->method_id_idx);
        const char *nn = file->getMethodName(cm->method_id_idx);
        const char *ccls = caller ? file->getMethodClass(caller->method_id_idx)
                                  : nullptr;
        const char *cnam = caller ? file->getMethodName(caller->method_id_idx)
                                  : nullptr;
        LOGDIAG("vm-debug: null object result (#%d): callee id=%u kind=%d %s.%s shorty=%s | caller=%s.%s call_pc=%d",
             g_nullVirtualResultCount.load(std::memory_order_relaxed), methodIdIdx, kind,
             nc ? nc : "?", nn ? nn : "?", shorty,
             ccls ? ccls : "(external)", cnam ? cnam : "?", pc);
        const uint16_t *cins = file->getInsns(cm);
        char chex[600];
        size_t co = 0;
        int cn_cnt = cm->insns_size < 64 ? cm->insns_size : 64;
        for (int i = 0; cins && i < cn_cnt && co + 5 < sizeof(chex); i++) {
            int cw = snprintf(chex + co, sizeof(chex) - co, "%04x",
                              (unsigned)fetch16(cins, i));
            if (cw > 0) co += (size_t)cw;
        }
        chex[co] = 0;
        LOGDIAG("  null-callee bytecode (%d units, first 64): %s",
             cm->insns_size, chex);
    }
    return !hasPendingException(env);
}

/** Field get/put: isGet means dstReg receives the value, otherwise it holds the
 *  source value; objReg is the receiver (unused when static). */
bool doFieldOp(JNIEnv *env, VmpFile *file, const Reg *v, Reg *w,
               uint32_t fieldIdx, bool isStatic, bool isGet,
               int dstReg, int objReg, int pc) {
    uint32_t cls, type, name;
    file->getFieldId(fieldIdx, &cls, &type, &name);
    const char *tdesc = file->getTypeDescriptor(type);
    if (!tdesc) return false;
    char t = tdesc[0];
    jfieldID fid = file->fieldOf(env, (int)fieldIdx, isStatic);
    if (!fid) return false;

    if (!isStatic && (!isGet || readCheckEnabled())) {
        jobject fo = vL(v, objReg);
        if (fo) {
            jclass dc = file->classOfType(env, (int)cls);
            if (dc && env->IsInstanceOf(fo, dc) != JNI_TRUE) {
                const char *cd = file->getTypeDescriptor((int)cls);
                LOGE("doFieldOp: FIELD RECEIVER MISMATCH field#%u (%s : %s)",
                     fieldIdx, cd ? cd : "?", tdesc);
                LOGE("  pc=%d receiverReg=v%d receiver=0x%llx",
                     pc, objReg, (unsigned long long)fo);
                if (ensureClassNameMid(env)) {
                    jclass oc = env->GetObjectClass(fo);
                    if (oc) {
                        jstring nm = (jstring)env->CallObjectMethod(oc, g_classGetNameMid);
                        if (nm && !env->ExceptionCheck()) {
                            const char *u = env->GetStringUTFChars(nm, nullptr);
                            LOGE("  actual receiver class: %s", u ? u : "?");
                            if (u) env->ReleaseStringUTFChars(nm, u);
                        }
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        env->DeleteLocalRef(nm);
                        env->DeleteLocalRef(oc);
                    } else if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                    }
                }
                jclass icce = env->FindClass("java/lang/IncompatibleClassChangeError");
                if (icce) {
                    env->ThrowNew(icce, "Internal error: field access on receiver of wrong class");
                    env->DeleteLocalRef(icce);
                }
                return false;
            }
        }
    }

    if (!isGet && (t == 'L' || t == '[')) {
        jobject val = vL(v, dstReg);
        if (val) {
            jclass dc = file->classOfType(env, (int)type);
            if (dc && env->IsInstanceOf(val, dc) != JNI_TRUE) {
                const char *cd = file->getTypeDescriptor((int)cls);
                LOGE("doFieldOp: FIELD TYPE MISMATCH iput into field#%u (%s : %s)",
                     fieldIdx, cd ? cd : "?", tdesc);
                LOGE("  pc=%d valueReg=v%d value=0x%llx",
                     pc, dstReg, (unsigned long long)val);
                if (ensureClassNameMid(env)) {
                    jclass oc = env->GetObjectClass(val);
                    if (oc) {
                        jstring nm = (jstring)env->CallObjectMethod(oc, g_classGetNameMid);
                        if (nm && !env->ExceptionCheck()) {
                            const char *u = env->GetStringUTFChars(nm, nullptr);
                            LOGE("  actual value class: %s", u ? u : "?");
                            if (u) env->ReleaseStringUTFChars(nm, u);
                        }
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        env->DeleteLocalRef(nm);
                        env->DeleteLocalRef(oc);
                    } else if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                    }
                }
                jclass icce = env->FindClass("java/lang/IncompatibleClassChangeError");
                if (icce) {
                    env->ThrowNew(icce, "Internal error: field store type mismatch");
                    env->DeleteLocalRef(icce);
                }
                return false;
            }
        }
    }

    if (isGet) {
        if (isStatic) {
            jclass c = file->classOfType(env, cls);
            if (!c) return false;
            switch (t) {
                case 'I': wI(w, dstReg, env->GetStaticIntField(c, fid)); break;
                case 'Z': wI(w, dstReg, env->GetStaticBooleanField(c, fid)); break;
                case 'B': wI(w, dstReg, env->GetStaticByteField(c, fid)); break;
                case 'C': wI(w, dstReg, env->GetStaticCharField(c, fid)); break;
                case 'S': wI(w, dstReg, env->GetStaticShortField(c, fid)); break;
                case 'J': wJ(w, dstReg, env->GetStaticLongField(c, fid)); break;
                case 'F': wF(w, dstReg, env->GetStaticFloatField(c, fid)); break;
                case 'D': wD(w, dstReg, env->GetStaticDoubleField(c, fid)); break;
                default:  wL(w, dstReg, env->GetStaticObjectField(c, fid)); break;
            }
        } else {
            jobject o = vL(v, objReg);
            if (!o) {
                throwJava(env, "java/lang/NullPointerException", "null receiver in iget");
                return false;
            }
            switch (t) {
                case 'I': wI(w, dstReg, env->GetIntField(o, fid)); break;
                case 'Z': wI(w, dstReg, env->GetBooleanField(o, fid)); break;
                case 'B': wI(w, dstReg, env->GetByteField(o, fid)); break;
                case 'C': wI(w, dstReg, env->GetCharField(o, fid)); break;
                case 'S': wI(w, dstReg, env->GetShortField(o, fid)); break;
                case 'J': wJ(w, dstReg, env->GetLongField(o, fid)); break;
                case 'F': wF(w, dstReg, env->GetFloatField(o, fid)); break;
                case 'D': wD(w, dstReg, env->GetDoubleField(o, fid)); break;
                default:  wL(w, dstReg, env->GetObjectField(o, fid)); break;
            }
        }
    } else {
        if (isStatic) {
            jclass c = file->classOfType(env, cls);
            if (!c) return false;
            switch (t) {
                case 'I': env->SetStaticIntField(c, fid, vI(v, dstReg)); break;
                case 'Z': env->SetStaticBooleanField(c, fid, (jboolean)vI(v, dstReg)); break;
                case 'B': env->SetStaticByteField(c, fid, (jbyte)vI(v, dstReg)); break;
                case 'C': env->SetStaticCharField(c, fid, (jchar)vI(v, dstReg)); break;
                case 'S': env->SetStaticShortField(c, fid, (jshort)vI(v, dstReg)); break;
                case 'J': env->SetStaticLongField(c, fid, vJ(v, dstReg)); break;
                case 'F': env->SetStaticFloatField(c, fid, vF(v, dstReg)); break;
                case 'D': env->SetStaticDoubleField(c, fid, vD(v, dstReg)); break;
                default:  env->SetStaticObjectField(c, fid, vL(v, dstReg)); break;
            }
        } else {
            jobject o = vL(v, objReg);
            if (!o) {
                throwJava(env, "java/lang/NullPointerException", "null receiver in iput");
                return false;
            }
            switch (t) {
                case 'I': env->SetIntField(o, fid, vI(v, dstReg)); break;
                case 'Z': env->SetBooleanField(o, fid, (jboolean)vI(v, dstReg)); break;
                case 'B': env->SetByteField(o, fid, (jbyte)vI(v, dstReg)); break;
                case 'C': env->SetCharField(o, fid, (jchar)vI(v, dstReg)); break;
                case 'S': env->SetShortField(o, fid, (jshort)vI(v, dstReg)); break;
                case 'J': env->SetLongField(o, fid, vJ(v, dstReg)); break;
                case 'F': env->SetFloatField(o, fid, vF(v, dstReg)); break;
                case 'D': env->SetDoubleField(o, fid, vD(v, dstReg)); break;
                default:  env->SetObjectField(o, fid, vL(v, dstReg)); break;
            }
        }
    }
    return !hasPendingException(env);
}

/** Element size (bytes) of a primitive JNI array from its runtime class
 *  ("[B" -> 1, "[J" -> 8, ...), or -1 when unknown. */
static int arrayElementSize(JNIEnv *env, jobject arr) {
    if (!arr) return -1;
    jclass cB = classOfDesc(env, "[B", 2);
    jclass cZ = classOfDesc(env, "[Z", 2);
    jclass cS = classOfDesc(env, "[S", 2);
    jclass cC = classOfDesc(env, "[C", 2);
    jclass cI = classOfDesc(env, "[I", 2);
    jclass cF = classOfDesc(env, "[F", 2);
    jclass cJ = classOfDesc(env, "[J", 2);
    jclass cD = classOfDesc(env, "[D", 2);
    if (cZ && env->IsInstanceOf(arr, cZ)) return 1;
    if (cB && env->IsInstanceOf(arr, cB)) return 1;
    if (cS && env->IsInstanceOf(arr, cS)) return 2;
    if (cC && env->IsInstanceOf(arr, cC)) return 2;
    if (cI && env->IsInstanceOf(arr, cI)) return 4;
    if (cF && env->IsInstanceOf(arr, cF)) return 4;
    if (cJ && env->IsInstanceOf(arr, cJ)) return 8;
    if (cD && env->IsInstanceOf(arr, cD)) return 8;
    return -1;
}

}

std::atomic<bool> g_vmpDebug{false};

void vmpSetInterpDebug(bool debug) {
    g_vmpDebug = debug;
    g_argCheckBudget = debug ? kArgCheckBudgetDebug : kArgCheckBudgetRelease;
    g_readCheckBudget = debug ? kReadCheckBudgetDebug : kReadCheckBudgetRelease;
    LOGI("interp: checks armed (debug=%d) argBudget=%d readBudget=%d "
         "then sample 1-in-%u",
         debug ? 1 : 0, g_argCheckBudget.load(std::memory_order_relaxed),
         g_readCheckBudget.load(std::memory_order_relaxed),
         kReadCheckSampleEvery);
}

VmResult vmInterpret(JNIEnv *env, jobject self, VmpFile *file,
                     const VmMethod *m, const jvalue *args, bool isStatic) {
    VmResult result;
    memset(&result.value, 0, sizeof(jvalue));

    if (env->PushLocalFrame(256) < 0) {
        result.exception = true;
        return result;
    }

    if (!file || !m) {
        throwJava(env, "java/lang/InternalError", "vm: null file or method");
        result.exception = true;
        env->PopLocalFrame(nullptr);
        return result;
    }

    const uint16_t *insns = file->getInsns(m);
    if (!insns) {
        throwJava(env, "java/lang/InternalError", "vm: no code");
        result.exception = true;
        env->PopLocalFrame(nullptr);
        return result;
    }

    const size_t insnsUnits = m->insns_size > 0 ? (size_t)m->insns_size : 0;
    std::vector<uint16_t> insnsPad(insnsUnits + 8u, 0xffff);
    memcpy(insnsPad.data(), insns, insnsUnits * 2u);
    insns = insnsPad.data();
#ifndef VMP_RELEASE_QUIET
    InsnReadScope insnRead(insns, insnsUnits);
#endif

    uint64_t *regs64 = new uint64_t[(size_t)m->regs + 4];
    memset(regs64, 0, sizeof(uint64_t) * ((size_t)m->regs + 4));
    Reg *v = (Reg *)regs64;

    const char *shorty = file->getMethodShorty(m->method_id_idx);
    int nparams = shorty ? (int)strlen(shorty) - 1 : 0;
    {
        int argSlots = m->ins - (isStatic ? 0 : 1);
        if (argSlots < 0) argSlots = 0;
        if (nparams > argSlots) {
            LOGE("vm-enter: shorty declares %d params but frame %s.%s has %d "
                 "arg register(s) - extras dropped",
                 nparams,
                 file->getMethodClass(m->method_id_idx) ?
                     file->getMethodClass(m->method_id_idx) : "?",
                 file->getMethodName(m->method_id_idx) ?
                     file->getMethodName(m->method_id_idx) : "?",
                 argSlots);
            nparams = argSlots;
        }
    }
    int r = m->regs - m->ins;
    if (!isStatic) { wL(v, r, self); r++; }
    for (int i = 0; i < nparams && r < m->regs; i++) {
        char t = shorty[i + 1];
        switch (t) {
            case 'L': wL(v, r, args[i].l); r++; break;
            case 'I': case 'Z': case 'B': case 'C': case 'S': wI(v, r, args[i].i); r++; break;
            case 'J': wJ(v, r, args[i].j); r += 2; break;
            case 'F': wF(v, r, args[i].f); r++; break;
            case 'D': wD(v, r, args[i].d); r += 2; break;
        }
    }

    int pc = 0;
    bool done = false;
    jobject pendingThrowable = nullptr;
    std::vector<jobject> enteredMonitors;
    jvalue lastResult; memset(&lastResult, 0, sizeof(lastResult));
    int handlerPc = -1;

    uint16_t histPc[16];
    uint16_t histOp[16];
    unsigned histN = 0;
    auto dumpVmState = [&](const char *why, uint32_t calleeIdx = 0xffffffffu) {
        static std::atomic<int> logged{0};
        if (logged.fetch_add(1, std::memory_order_relaxed) >= 6) return;
        const char *cls = file->getMethodClass(m->method_id_idx);
        const char *nm = file->getMethodName(m->method_id_idx);
#ifdef VMP_RELEASE_QUIET
        LOGE("vmstate (%s): method=%s.%s cur_pc=%d",
             why, cls ? cls : "?", nm ? nm : "?", pc);
#else
        char hexbuf[600];
        size_t ho = 0;
        int n = m->insns_size < 64 ? m->insns_size : 64;
        for (int i = 0; i < n && ho + 5 < sizeof(hexbuf); i++) {
            int w = snprintf(hexbuf + ho, sizeof(hexbuf) - ho, "%04x",
                             (unsigned)fetch16(insns, i));
            if (w > 0) ho += (size_t)w;
        }
        hexbuf[ho] = 0;
        char histbuf[512];
        size_t h2 = 0;
        unsigned start = histN > 16u ? histN - 16u : 0u;
        for (unsigned k = start; k < histN && h2 + 32 < sizeof(histbuf); k++) {
            int w = snprintf(histbuf + h2, sizeof(histbuf) - h2, "[%u]pc=%d op=%02x ",
                             k, (int)histPc[k & 15], (unsigned)histOp[k & 15]);
            if (w > 0) h2 += (size_t)w;
        }
        histbuf[h2] = 0;
        LOGE("vmstate (%s): method=%s.%s insns_size=%d cur_pc=%d insns[%d]=%s | hist: %s",
             why, cls ? cls : "?", nm ? nm : "?",
             m->insns_size, pc, n, hexbuf, histbuf);
#endif
        if (calleeIdx != 0xffffffffu) {
            const char *cc = file->getMethodClass((int)calleeIdx);
            const char *cn = file->getMethodName((int)calleeIdx);
            const char *cs = file->getMethodSig((int)calleeIdx);
            LOGE("  uncaught from invoke at pc=%d: callee=%s.%s%s",
                 pc, cc ? cc : "?", cn ? cn : "?", cs ? cs : "?");
        }
    };

    const uint32_t *tries = file->getTries(m);
    int triesSize = m->tries_size;

    auto routeException = [&]() -> bool {
        jobject t = takePendingException(env);
        if (!t) return true;
        pendingThrowable = t;
        int hp = findCatchHandler(tries, triesSize, pc, t, env, file);
        if (hp >= 0) { pc = hp; handlerPc = hp; return true; }
        rethrow(env, t);
        pendingThrowable = nullptr;
        return false;
    };

    auto failSilent = [&](const char *what) -> bool {
        if (!hasPendingException(env)) {
            jclass ie = env->FindClass("java/lang/InternalError");
            if (ie) {
                env->ThrowNew(ie, what ? what : "Internal error: execution failed");
                env->DeleteLocalRef(ie);
            }
        }
        return routeException();
    };

    auto failArith = [&]() -> bool {
        if (!hasPendingException(env)) {
            jclass ae = env->FindClass("java/lang/ArithmeticException");
            if (ae) {
                env->ThrowNew(ae, "divide by zero by integer division");
                env->DeleteLocalRef(ae);
            }
        }
        return routeException();
    };

    auto forgetEnteredMonitor = [&](jobject monitor) {
        for (auto it = enteredMonitors.rbegin(); it != enteredMonitors.rend(); ++it) {
            if (env->IsSameObject(*it, monitor) == JNI_TRUE) {
                enteredMonitors.erase(std::next(it).base());
                return;
            }
        }
    };

    int pendingResultPc = -1;
    int pendingResultReg = -1;
    int lastResultMethodId = -1;

    while (!done && !hasPendingException(env) && pc >= 0 && pc < m->insns_size) {
#ifndef VMP_RELEASE_QUIET
        if (g_insnReadPast) {
            g_insnReadPast = false;
            dumpVmState("operand read past the end of the method's stream");
            const char *tCls = file->getMethodClass(m->method_id_idx);
            const char *tNm = file->getMethodName(m->method_id_idx);
            LOGE("vm-truncated: %s.%s read past pc=%d (insns_size=%d)",
                 tCls ? tCls : "?", tNm ? tNm : "?", pc, m->insns_size);
            throwJava(env, "java/lang/InternalError",
                      "Internal error: instruction stream truncated");
            done = true;
            result.exception = true;
            break;
        }
#endif
        uint16_t code = fetch16(insns, pc);
        uint8_t op = code & 0xff;
        int next = pc + 1;
        histPc[histN & 15] = (uint16_t)pc;
        histOp[histN & 15] = op;
        histN++;

        if (g_vmpDebug && g_loggedNullResult < 4 && pendingResultPc >= 0 && code == 0x6e) {
            int argCount = (code >> 12) & 0xf;
            if (argCount >= 1) {
                int receiverReg = fetch16(insns, pc + 2) & 0xf;
                if (receiverReg == pendingResultReg && vL(v, receiverReg) == nullptr) {
                    g_loggedNullResult++;
                    const VmMethod *culprit = methodByIdx(file, lastResultMethodId);
                    const char *culpritClass = culprit
                        ? file->getMethodClass(culprit->method_id_idx) : nullptr;
                    const char *culpritName = culprit
                        ? file->getMethodName(culprit->method_id_idx) : nullptr;
                    const char *culpritSig = culprit
                        ? file->getMethodSig(culprit->method_id_idx) : nullptr;
                    LOGE("null-result trace: invoke at pc=%d returned null in "
                         "register v%d (receiver of the failing call at pc=%d) - "
                         "virtualized culprit: %s.%s%s",
                         pendingResultPc, receiverReg, pc,
                         culpritClass ? culpritClass : "?",
                         culpritName ? culpritName : "?",
                         culpritSig ? culpritSig : "?");
                    if (culprit) {
                        char hexbuf[600];
                        size_t ho = 0;
                        int n = culprit->insns_size < 64 ? culprit->insns_size : 64;
                        const uint16_t *cins = file->getInsns(culprit);
                        for (int i = 0; cins && i < n && ho + 5 < sizeof(hexbuf); i++) {
                            int w = snprintf(hexbuf + ho, sizeof(hexbuf) - ho, "%04x",
                                             (unsigned)fetch16(cins, i));
                            if (w > 0) ho += (size_t)w;
                        }
                        hexbuf[ho] = 0;
                        LOGE("null-result trace: culprit bytecode (%d units, first 64): %s",
                             culprit->insns_size, hexbuf);
                    }
                    pendingResultPc = -1;
                }
            }
        }

        switch (op) {
            case 0x00: break;
            case 0x0e: done = true; break;

            case 0xfa:
            case 0xfe: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                uint32_t fidx = fetch16(insns, pc + 1);
                if (!doFieldOp(env, file, v, v, fidx, false, /*isGet=*/false, A, B, pc)) {
                    LOGDIAG("fused field put: marker=0x%x idx=%u A=v%d B=v%d pc=%d",
                         op, fidx, A, B, pc);
                    if (!failSilent("Internal error: fused field op failed")) { done = true; result.exception = true; }
                }
                next = pc + 2;
                break;
            }
            case 0xfb:
            case 0xff: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                uint32_t fidx = fetch16(insns, pc + 1);
                if (!doFieldOp(env, file, v, v, fidx, false, /*isGet=*/true, A, B, pc)) {
                    LOGDIAG("fused field get: marker=0x%x idx=%u A=v%d B=v%d pc=%d",
                         op, fidx, A, B, pc);
                    if (!failSilent("Internal error: fused field op failed")) { done = true; result.exception = true; }
                }
                next = pc + 2;
                break;
            }
            case 0xfc: {
                int A = (code >> 8) & 0xff;
                wI(v, A, (int32_t)(int16_t)fetch16(insns, pc + 1));
                next = pc + 2;
                break;
            }
            case 0xfd: {
                int A = (code >> 8) & 0xff;
                wJ(v, A, (int64_t)(int16_t)fetch16(insns, pc + 1));
                next = pc + 2;
                break;
            }

            case 0x0a: wI(v, (code >> 8) & 0xff, lastResult.i); break;
            case 0x0b: wJ(v, (code >> 8) & 0xff, lastResult.j); break;
            case 0x0c: {
                wL(v, (code >> 8) & 0xff, lastResult.l);
                if (histN >= 2) {
                    pendingResultPc = (int)histPc[(histN - 2) & 15];
                    pendingResultReg = (code >> 8) & 0xff;
                }
                break;
            }
            case 0x0d: {
                wL(v, (code >> 8) & 0xff, pendingThrowable);
                pendingThrowable = nullptr;
                break;
            }
            case 0x0f: result.value.i = vI(v, (code >> 8) & 0xff); done = true; break;
            case 0x10: result.value.j = vJ(v, (code >> 8) & 0xff); done = true; break;
            case 0x11: {
                jobject rv = vL(v, (code >> 8) & 0xff);
                if (rv) {
                    const char *sig = file->getMethodSig(m->method_id_idx);
                    const char *ret = sig ? strchr(sig, ')') : nullptr;
                    if (ret && (ret[1] == 'L' || ret[1] == '[')) {
                        jclass dc = classOfDesc(env, ret + 1, (int)strlen(ret + 1));
                        if (dc && env->IsInstanceOf(rv, dc) != JNI_TRUE) {
                            const char *mc = file->getMethodClass(m->method_id_idx);
                            const char *mn = file->getMethodName(m->method_id_idx);
                            LOGE("vm-return-type mismatch: %s.%s%s",
                                 mc ? mc : "?", mn ? mn : "?", sig ? sig : "");
                            LOGE("  pc=%d retReg=v%d value=0x%llx",
                                 pc, (code >> 8) & 0xff, (unsigned long long)rv);
                            if (ensureClassNameMid(env)) {
                                jclass oc = env->GetObjectClass(rv);
                                if (oc) {
                                    jstring nm = (jstring)env->CallObjectMethod(oc, g_classGetNameMid);
                                    if (nm && !env->ExceptionCheck()) {
                                        const char *u = env->GetStringUTFChars(nm, nullptr);
                                        LOGE("  actual returned class: %s", u ? u : "?");
                                        if (u) env->ReleaseStringUTFChars(nm, u);
                                    }
                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                    env->DeleteLocalRef(nm);
                                    env->DeleteLocalRef(oc);
                                } else if (env->ExceptionCheck()) {
                                    env->ExceptionClear();
                                }
                            }
#ifndef VMP_RELEASE_QUIET
                            {
                                const uint16_t *cins = file->getInsns(m);
                                char chex[600];
                                size_t co = 0;
                                int cn_cnt = m->insns_size < 64 ? m->insns_size : 64;
                                for (int i = 0; cins && i < cn_cnt && co + 5 < sizeof(chex); i++) {
                                    int cw = snprintf(chex + co, sizeof(chex) - co, "%04x",
                                                      (unsigned)fetch16(cins, i));
                                    if (cw > 0) co += (size_t)cw;
                                }
                                chex[co] = 0;
                                LOGE("  method bytecode (%d units, first 64): %s",
                                     m->insns_size, chex);
                            }
#endif
                            jclass icce = env->FindClass("java/lang/IncompatibleClassChangeError");
                            if (icce) {
                                env->ThrowNew(icce, "Internal error: return type mismatch");
                                env->DeleteLocalRef(icce);
                            }
                            if (!routeException()) { done = true; result.exception = true; }
                            break;
                        }
                    }
                }
                result.value.l = rv;
                done = true;
                break;
            }
            case 0x1d: {
                jobject mon = vL(v, (code >> 8) & 0xff);
                if (!mon) {
                    throwJava(env, "java/lang/NullPointerException", "null monitor");
                    if (!routeException()) { done = true; result.exception = true; }
                } else {
                    const jint monitorResult = env->MonitorEnter(mon);
                    if (monitorResult == JNI_OK && !hasPendingException(env))
                        enteredMonitors.push_back(mon);
                    if (!routeException()) { done = true; result.exception = true; }
                }
                break;
            }
            case 0x1e: {
                jobject mon = vL(v, (code >> 8) & 0xff);
                if (!mon) {
                    throwJava(env, "java/lang/NullPointerException", "null monitor");
                    if (!routeException()) { done = true; result.exception = true; }
                } else {
                    const jint monitorResult = env->MonitorExit(mon);
                    if (monitorResult == JNI_OK && !hasPendingException(env))
                        forgetEnteredMonitor(mon);
                    if (!routeException()) { done = true; result.exception = true; }
                }
                break;
            }
            case 0x27: {
                jobject obj = vL(v, (code >> 8) & 0xff);
                if (!obj) {
                    throwJava(env, "java/lang/NullPointerException", "null throw");
                    if (!routeException()) { done = true; result.exception = true; }
                } else {
                    env->Throw((jthrowable)obj);
                    if (!routeException()) { done = true; result.exception = true; }
                }
                break;
            }

            case 0x01: case 0x04: case 0x07: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                if (op == 0x04) { wJ(v, A, vJ(v, B)); }
                else { v[A] = v[B]; }
                break;
            }
            case 0x21: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                jarray arr = (jarray)vL(v, B);
                if (!arr) {
                    throwJava(env, "java/lang/NullPointerException", "null array length");
                    if (!routeException()) { done = true; result.exception = true; }
                } else {
                    wI(v, A, (int32_t)env->GetArrayLength(arr));
                }
                break;
            }
            case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f: case 0x80: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                switch (op) {
                    case 0x7b: wI(v, A, wrapNeg32(vI(v, B))); break;
                    case 0x7c: wI(v, A, ~vI(v, B)); break;
                    case 0x7d: wJ(v, A, wrapNeg64(vJ(v, B))); break;
                    case 0x7e: wJ(v, A, ~vJ(v, B)); break;
                    case 0x7f: wF(v, A, -vF(v, B)); break;
                    case 0x80: wD(v, A, -vD(v, B)); break;
                }
                break;
            }
            case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
            case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c:
            case 0x8d: case 0x8e: case 0x8f: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                switch (op) {
                    case 0x81: wJ(v, A, (int64_t)vI(v, B)); break;
                    case 0x82: wF(v, A, (float)vI(v, B)); break;
                    case 0x83: wD(v, A, (double)vI(v, B)); break;
                    case 0x84: wI(v, A, (int32_t)vJ(v, B)); break;
                    case 0x85: wF(v, A, (float)vJ(v, B)); break;
                    case 0x86: wD(v, A, (double)vJ(v, B)); break;
                    case 0x87: wI(v, A, dalvikFpToInt((double)vF(v, B))); break;
                    case 0x88: wJ(v, A, dalvikFpToLong((double)vF(v, B))); break;
                    case 0x89: wD(v, A, (double)vF(v, B)); break;
                    case 0x8a: wI(v, A, dalvikFpToInt(vD(v, B))); break;
                    case 0x8b: wJ(v, A, dalvikFpToLong(vD(v, B))); break;
                    case 0x8c: wF(v, A, (float)vD(v, B)); break;
                    case 0x8d: wI(v, A, (int8_t)vI(v, B)); break;
                    case 0x8e: wI(v, A, (uint16_t)vI(v, B)); break;
                    case 0x8f: wI(v, A, (int16_t)vI(v, B)); break;
                }
                break;
            }
            case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
            case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                int32_t x = vI(v, A), y = vI(v, B);
                bool wrote = true;
                switch (op) {
                    case 0xb0: x = wrapAdd32(x, y); break;
                    case 0xb1: x = wrapSub32(x, y); break;
                    case 0xb2: x = wrapMul32(x, y); break;
                    case 0xb3: case 0xb4: {
                        if (y == 0) {
                            wrote = false;
                            if (!failArith()) { done = true; result.exception = true; }
                        } else if (op == 0xb3) x = dalvikDiv32(x, y);
                        else x = dalvikRem32(x, y);
                        break;
                    }
                    case 0xb5: x &= y; break; case 0xb6: x |= y; break; case 0xb7: x ^= y; break;
                    case 0xb8: x = (int32_t)((uint32_t)x << (y & 31)); break;
                    case 0xb9: x = x >> (y & 31); break;
                    case 0xba: x = (int32_t)((uint32_t)x >> (y & 31)); break;
                }
                if (wrote) wI(v, A, x);
                break;
            }
            case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0:
            case 0xc1: case 0xc2: case 0xc3: case 0xc4: case 0xc5: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                int64_t x = vJ(v, A), y = vJ(v, B);
                bool wrote = true;
                switch (op) {
                    case 0xbb: x = wrapAdd64(x, y); break;
                    case 0xbc: x = wrapSub64(x, y); break;
                    case 0xbd: x = wrapMul64(x, y); break;
                    case 0xbe: case 0xbf: {
                        if (y == 0) {
                            wrote = false;
                            if (!failArith()) { done = true; result.exception = true; }
                        } else if (op == 0xbe) x = dalvikDiv64(x, y);
                        else x = dalvikRem64(x, y);
                        break;
                    }
                    case 0xc0: x &= y; break; case 0xc1: x |= y; break; case 0xc2: x ^= y; break;
                    case 0xc3: x = (int64_t)((uint64_t)x << (y & 63)); break;
                    case 0xc4: x = x >> (y & 63); break;
                    case 0xc5: x = (int64_t)((uint64_t)x >> (y & 63)); break;
                }
                if (wrote) wJ(v, A, x);
                break;
            }
            case 0xc6: case 0xc7: case 0xc8: case 0xc9: case 0xca: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                float x = vF(v, A), y = vF(v, B);
                switch (op) {
                    case 0xc6: x += y; break; case 0xc7: x -= y; break;
                    case 0xc8: x *= y; break; case 0xc9: x /= y; break; case 0xca: x = fmodf(x, y); break;
                }
                wF(v, A, x);
                break;
            }
            case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                double x = vD(v, A), y = vD(v, B);
                switch (op) {
                    case 0xcb: x += y; break; case 0xcc: x -= y; break;
                    case 0xcd: x *= y; break; case 0xce: x /= y; break; case 0xcf: x = fmod(x, y); break;
                }
                wD(v, A, x);
                break;
            }

            case 0x12: {
                int A = (code >> 8) & 0xf;
                int8_t lit = (int8_t)((code >> 12) & 0xf);
                if (lit & 0x8) lit |= 0xf0;
                wI(v, A, (int32_t)lit);
                break;
            }

            case 0x28: next = pc + (int8_t)(code >> 8); break;

            case 0x29: {
                next = pc + (int16_t)fetch16(insns, pc + 1);
                break;
            }

            case 0x2a: {
                int32_t off = (int32_t)(uint32_t)(fetch16(insns, pc + 1) |
                                                  ((uint32_t)fetch16(insns, pc + 2) << 16));
                next = pc + off;
                break;
            }

            case 0x02: case 0x05: case 0x08: {
                int A = (code >> 8) & 0xff;
                int B = fetch16(insns, pc + 1);
                if (op == 0x05) wJ(v, A, vJ(v, B)); else v[A] = v[B];
                next = pc + 2;
                break;
            }

            case 0x03: case 0x06: case 0x09: {
                int A = fetch16(insns, pc + 1);
                int B = fetch16(insns, pc + 2);
                if (op == 0x06) wJ(v, A, vJ(v, B)); else v[A] = v[B];
                next = pc + 3;
                break;
            }

            case 0x13: case 0x15: case 0x16: case 0x19: {
                int A = (code >> 8) & 0xff;
                int16_t lit = (int16_t)fetch16(insns, pc + 1);
                if (op == 0x13 || op == 0x16) { if (op == 0x16) wJ(v, A, (int64_t)lit); else wI(v, A, (int32_t)lit); }
                else if (op == 0x15) wI(v, A, (int32_t)((uint32_t)(uint16_t)lit << 16));
                else wJ(v, A, (int64_t)((uint64_t)(uint16_t)lit << 48));
                next = pc + 2;
                break;
            }

            case 0x14: case 0x17: {
                int A = (code >> 8) & 0xff;
                int32_t lit = (int32_t)((uint32_t)fetch16(insns, pc + 1) |
                                        ((uint32_t)fetch16(insns, pc + 2) << 16));
                if (op == 0x17) wJ(v, A, (int64_t)lit); else wI(v, A, lit);
                next = pc + 3;
                break;
            }

            case 0x18: {
                int A = (code >> 8) & 0xff;
                int64_t w = (int64_t)fetch16(insns, pc + 1) |
                            ((int64_t)fetch16(insns, pc + 2) << 16) |
                            ((int64_t)fetch16(insns, pc + 3) << 32) |
                            ((int64_t)fetch16(insns, pc + 4) << 48);
                wJ(v, A, w);
                next = pc + 5;
                break;
            }

            case 0x1a: {
                int A = (code >> 8) & 0xff;
                const char *s = file->getStringById(fetch16(insns, pc + 1));
                if (!s) {
                    if (!failSilent("Internal error: const-string: unresolved string id")) {
                        done = true; result.exception = true;
                    }
                    next = pc + 2;
                    break;
                }
                jstring js = env->NewStringUTF(s);
                wL(v, A, js);
                next = pc + 2;
                break;
            }
            case 0x1b: {
                int A = (code >> 8) & 0xff;
                uint32_t idx = (uint32_t)fetch16(insns, pc + 1) |
                               ((uint32_t)fetch16(insns, pc + 2) << 16);
                const char *s = file->getStringById(idx);
                if (!s) {
                    if (!failSilent("Internal error: const-string/jumbo: unresolved string id")) {
                        done = true; result.exception = true;
                    }
                    next = pc + 3;
                    break;
                }
                jstring js = env->NewStringUTF(s);
                wL(v, A, js);
                next = pc + 3;
                break;
            }
            case 0x1c: {
                int A = (code >> 8) & 0xff;
                jclass c = file->classOfType(env, fetch16(insns, pc + 1));
                if (!c) {
                    if (!failSilent("Internal error: const-class: unresolved type")) {
                        done = true; result.exception = true;
                    }
                } else {
                    wL(v, A, c);
                }
                next = pc + 2;
                break;
            }
            case 0x1f: {
                int A = (code >> 8) & 0xff;
                jobject obj = vL(v, A);
                jclass c = file->classOfType(env, fetch16(insns, pc + 1));
                if (obj && c && !env->IsInstanceOf(obj, c)) {
                    const char *cd = file->getTypeDescriptor(fetch16(insns, pc + 1));
                    LOGE("check-cast FAILED pc=%d reg=v%d expected=%s",
                         pc, A, cd ? cd : "?");
                    if (ensureClassNameMid(env)) {
                        jclass oc = env->GetObjectClass(obj);
                        if (oc) {
                            jstring nm = (jstring)env->CallObjectMethod(oc, g_classGetNameMid);
                            if (nm && !env->ExceptionCheck()) {
                                const char *u = env->GetStringUTFChars(nm, nullptr);
                                LOGE("  actual object class: %s", u ? u : "?");
                                if (u) env->ReleaseStringUTFChars(nm, u);
                            }
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            env->DeleteLocalRef(nm);
                            env->DeleteLocalRef(oc);
                        } else if (env->ExceptionCheck()) {
                            env->ExceptionClear();
                        }
                    }
                    {
                        const char *cc = file->getMethodClass(m->method_id_idx);
                        const char *cn = file->getMethodName(m->method_id_idx);
                        LOGE("  in method: %s.%s (reg=%d regs=%d pc=%d)",
                             cc ? cc : "?", cn ? cn : "?", A, m->regs, pc);
                    }
                    throwJava(env, "java/lang/ClassCastException", "check-cast");
                    if (!routeException()) { done = true; result.exception = true; }
                }
                if (!c) {
                    if (!failSilent("Internal error: check-cast: unresolved type")) {
                        done = true; result.exception = true;
                    }
                }
                next = pc + 2;
                break;
            }
            case 0x22: {
                int A = (code >> 8) & 0xff;
                lastResultMethodId = -1;
                pendingResultPc = -1;
                jclass c = file->classOfType(env, fetch16(insns, pc + 1));
                jobject o = c ? env->AllocObject(c) : nullptr;
                if (!o) {
                    if (!failSilent("Internal error: new-instance: unresolved class")) {
                        done = true; result.exception = true;
                    }
                } else {
                    wL(v, A, o);
                }
                next = pc + 2;
                break;
            }
            case 0x23: {
                int A = (code >> 8) & 0xf;
                int B = (code >> 12) & 0xf;
                jsize size = vI(v, B);
                const char *desc = file->getTypeDescriptor(fetch16(insns, pc + 1));
                const size_t dl = desc ? strlen(desc) : 0;
                jobject arr = nullptr;
                if (desc && desc[0] == '[') {
                    if (desc[1] == 'L' && dl >= 3) {
                        std::string elem(desc + 2, dl - 3);
                        jclass elemCls = env->FindClass(elem.c_str());
                        if (elemCls) arr = env->NewObjectArray(size, elemCls, nullptr);
                    } else if (desc[1] == '[') {
                        std::string elem(desc + 1, strlen(desc) - 1);
                        jclass elemCls = env->FindClass(elem.c_str());
                        if (elemCls) arr = env->NewObjectArray(size, elemCls, nullptr);
                    } else {
                        switch (desc[1]) {
                            case 'Z': arr = env->NewBooleanArray(size); break;
                            case 'B': arr = env->NewByteArray(size); break;
                            case 'S': arr = env->NewShortArray(size); break;
                            case 'C': arr = env->NewCharArray(size); break;
                            case 'I': arr = env->NewIntArray(size); break;
                            case 'J': arr = env->NewLongArray(size); break;
                            case 'F': arr = env->NewFloatArray(size); break;
                            case 'D': arr = env->NewDoubleArray(size); break;
                        }
                    }
                }
                if (!arr || hasPendingException(env)) {
                    if (!failSilent("Internal error: new-array: unresolved type")) {
                        done = true; result.exception = true;
                    }
                } else {
                    wL(v, A, arr);
                }
                next = pc + 2;
                break;
            }

            case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66:
            case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
                int A = (code >> 8) & 0xff;
                bool isGet = op < 0x67;
                if (!doFieldOp(env, file, v, v, fetch16(insns, pc + 1), true, isGet, A, 0, pc)) {
                    if (!failSilent("Internal error: static field op failed")) { done = true; result.exception = true; }
                }
                next = pc + 2;
                break;
            }

            case 0x26: {
                int A = (code >> 8) & 0xff;
                int32_t off = (int32_t)(uint32_t)(fetch16(insns, pc + 1) |
                                                  ((uint32_t)fetch16(insns, pc + 2) << 16));
                int64_t ppcWide = (int64_t)pc + (int64_t)off;
                int ppc = (ppcWide < 0 || ppcWide > 0x40000000LL) ? -1 : (int)ppcWide;
                if (ppc >= 0 && ppc + 3 < m->insns_size) {
                    uint16_t ident = fetch16(insns, ppc);
                    uint16_t ew = fetch16(insns, ppc + 1);
                    uint32_t cnt = fetch16(insns, ppc + 2) | (fetch16(insns, ppc + 3) << 16);
                    if ((uint64_t)ppc + 4 + (((uint64_t)cnt * (uint64_t)(ew ? ew : 1)) + 1) / 2 >
                        (uint64_t)m->insns_size) {
                        next = pc + 3;
                        break;
                    }
                    jobject arr = vL(v, A);
                    bool fillFailed = false;
                    if (!arr) {
                        throwJava(env, "java/lang/NullPointerException", "null array in fill-array-data");
                        fillFailed = true;
                    } else if (ident != 0x0300) {
                    } else {
                        jsize alen = env->GetArrayLength((jarray)arr);
                        int aesz = arrayElementSize(env, arr);
                        if (aesz <= 0 || (int)ew != aesz) {
                            LOGE("vm payload width mismatch: %u vs %d",
                                 ew, aesz);
                            throwJava(env, "java/lang/InternalError",
                                      "Internal error: fill-array-data element width mismatch");
                            fillFailed = true;
                        } else if ((uint64_t)cnt > (uint64_t)alen) {
                            char fmsg[96];
                            snprintf(fmsg, sizeof(fmsg),
                                     "Internal error: fill-array-data count %u exceeds array length %d",
                                     cnt, alen);
                            LOGE("%s", fmsg);
                            throwJava(env, "java/lang/ArrayIndexOutOfBoundsException", fmsg);
                            fillFailed = true;
                        }
                    }
                    if (!fillFailed && ident == 0x0300) {
                        if (ew == 1) {
                            std::vector<jbyte> b(cnt);
                            for (uint32_t i=0;i<cnt;i++){ uint16_t w=fetch16(insns, ppc+4+i/2); b[i]=(jbyte)((i & 1) ? (w >> 8) : (w & 0xff)); }
                            jclass cz = classOfDesc(env, "[Z", 2);
                            if (cz && env->IsInstanceOf(arr, cz))
                                env->SetBooleanArrayRegion((jbooleanArray)arr, 0, (jsize)cnt, (const jboolean *)b.data());
                            else
                                env->SetByteArrayRegion((jbyteArray)arr, 0, (jsize)cnt, b.data());
                        }
                        else if (ew == 2) {
                            std::vector<jshort> b(cnt);
                            for (uint32_t i=0;i<cnt;i++) b[i]=(jshort)fetch16(insns, ppc+4+i);
                            jclass cc = classOfDesc(env, "[C", 2);
                            if (cc && env->IsInstanceOf(arr, cc))
                                env->SetCharArrayRegion((jcharArray)arr, 0, (jsize)cnt, (const jchar *)b.data());
                            else
                                env->SetShortArrayRegion((jshortArray)arr, 0, (jsize)cnt, b.data());
                        }
                        else if (ew == 4) {
                            jclass ci = classOfDesc(env, "[I", 2);
                            if (ci && env->IsInstanceOf(arr, ci)) {
                                std::vector<jint> b(cnt); for (uint32_t i=0;i<cnt;i++) b[i]=(jint)(fetch16(insns, ppc+4+i*2) | (fetch16(insns, ppc+5+i*2)<<16)); env->SetIntArrayRegion((jintArray)arr, 0, (jsize)cnt, b.data());
                            } else {
                                jclass cf = classOfDesc(env, "[F", 2);
                                if (cf && env->IsInstanceOf(arr, cf)) {
                                    std::vector<jfloat> b(cnt); for (uint32_t i=0;i<cnt;i++){ uint32_t u=(uint32_t)(fetch16(insns, ppc+4+i*2) | (fetch16(insns, ppc+5+i*2)<<16)); jfloat f; memcpy(&f, &u, 4); b[i]=f; } env->SetFloatArrayRegion((jfloatArray)arr, 0, (jsize)cnt, b.data());
                                }
                            }
                        }
                        else if (ew == 8) {
                            jclass cj = classOfDesc(env, "[J", 2);
                            if (cj && env->IsInstanceOf(arr, cj)) {
                                std::vector<jlong> b(cnt); for (uint32_t i=0;i<cnt;i++){ uint64_t u=(uint64_t)(fetch16(insns,ppc+4+i*4))|((uint64_t)fetch16(insns,ppc+5+i*4)<<16)|((uint64_t)fetch16(insns,ppc+6+i*4)<<32)|((uint64_t)fetch16(insns,ppc+7+i*4)<<48); b[i]=(jlong)u;} env->SetLongArrayRegion((jlongArray)arr, 0, (jsize)cnt, b.data());
                            } else {
                                jclass cd = classOfDesc(env, "[D", 2);
                                if (cd && env->IsInstanceOf(arr, cd)) {
                                    std::vector<jdouble> b(cnt); for (uint32_t i=0;i<cnt;i++){ uint64_t u=(uint64_t)(fetch16(insns,ppc+4+i*4))|((uint64_t)fetch16(insns,ppc+5+i*4)<<16)|((uint64_t)fetch16(insns,ppc+6+i*4)<<32)|((uint64_t)fetch16(insns,ppc+7+i*4)<<48); jdouble d; memcpy(&d, &u, 8); b[i]=d; } env->SetDoubleArrayRegion((jdoubleArray)arr, 0, (jsize)cnt, b.data());
                                }
                            }
                        }
                    }
                    if (!routeException()) { done = true; result.exception = true; }
                }
                next = pc + 3;
                break;
            }
            case 0x2b: {
                int A = (code >> 8) & 0xff;
                int32_t off = (int32_t)(uint32_t)(fetch16(insns, pc + 1) |
                                                  ((uint32_t)fetch16(insns, pc + 2) << 16));
                int64_t ppcWide = (int64_t)pc + (int64_t)off;
                int ppc = (ppcWide < 0 || ppcWide > 0x40000000LL) ? -1 : (int)ppcWide;
                int32_t sel = vI(v, A);
                if (ppc >= 0 && ppc + 2 < m->insns_size && fetch16(insns, ppc) == 0x0100) {
                    uint32_t size = fetch16(insns, ppc + 1);
                    if (size != 0 && ppc + 4 + (uint64_t)size * 2 <= (uint64_t)m->insns_size) {
                        int32_t first = (int32_t)(uint32_t)(fetch16(insns, ppc + 2) | ((uint32_t)fetch16(insns, ppc + 3) << 16));
                        int64_t idx = (int64_t)sel - (int64_t)first;
                        if (idx >= 0 && (uint64_t)idx < size) {
                            int32_t tgt = (int32_t)(uint32_t)(fetch16(insns, ppc + 4 + (int)idx * 2) | ((uint32_t)fetch16(insns, ppc + 5 + (int)idx * 2) << 16));
                            next = pc + tgt;
                            break;
                        }
                    }
                }
                next = pc + 3;
                break;
            }
            case 0x2c: {
                int A = (code >> 8) & 0xff;
                int32_t off = (int32_t)(uint32_t)(fetch16(insns, pc + 1) |
                                                  ((uint32_t)fetch16(insns, pc + 2) << 16));
                int64_t ppcWide = (int64_t)pc + (int64_t)off;
                int ppc = (ppcWide < 0 || ppcWide > 0x40000000LL) ? -1 : (int)ppcWide;
                int32_t sel = vI(v, A);
                bool jumped = false;
                if (ppc >= 0 && ppc + 2 < m->insns_size && fetch16(insns, ppc) == 0x0200) {
                    uint32_t size = fetch16(insns, ppc + 1);
                    if (size != 0 && ppc + 2 + (uint64_t)size * 4 <= (uint64_t)m->insns_size) {
                        uint32_t base = 2 + size * 2;
                        for (uint32_t i = 0; i < size; i++) {
                            int32_t key = (int32_t)(uint32_t)(fetch16(insns, ppc + 2 + i * 2) | ((uint32_t)fetch16(insns, ppc + 3 + i * 2) << 16));
                            if (key == sel) {
                                int32_t tgt = (int32_t)(uint32_t)(fetch16(insns, ppc + base + i * 2) | ((uint32_t)fetch16(insns, ppc + base + 1 + i * 2) << 16));
                                next = pc + tgt;
                                jumped = true;
                                break;
                            }
                        }
                    }
                }
                if (!jumped) next = pc + 3;
                break;
            }

            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                bool t = false;
                if (op == 0x32) t = regIsObj(v, A) ? env->IsSameObject(vL(v, A), vL(v, B)) : vI(v, A) == vI(v, B);
                else if (op == 0x33) t = regIsObj(v, A) ? !env->IsSameObject(vL(v, A), vL(v, B)) : vI(v, A) != vI(v, B);
                else {
                    int32_t x = vI(v, A), y = vI(v, B);
                    switch (op) { case 0x34: t = x < y; break; case 0x35: t = x >= y; break;
                        case 0x36: t = x > y; break; case 0x37: t = x <= y; break; }
                }
                if (t) next = pc + (int16_t)fetch16(insns, pc + 1);
                else next = pc + 2;
                break;
            }
            case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: {
                int A = (code >> 8) & 0xff;
                bool t = false;
                if (op == 0x38) t = regIsObj(v, A) ? env->IsSameObject(vL(v, A), nullptr) : vI(v, A) == 0;
                else if (op == 0x39) t = regIsObj(v, A) ? !env->IsSameObject(vL(v, A), nullptr) : vI(v, A) != 0;
                else {
                    int32_t x = vI(v, A);
                    switch (op) { case 0x3a: t = x < 0; break; case 0x3b: t = x >= 0; break;
                        case 0x3c: t = x > 0; break; case 0x3d: t = x <= 0; break; }
                }
                if (t) next = pc + (int16_t)fetch16(insns, pc + 1);
                else next = pc + 2;
                break;
            }

            case 0x2d: case 0x2e: case 0x2f: case 0x30: case 0x31: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff, C = (u1 >> 8) & 0xff;
                int32_t r = 0;
                if (op == 0x31) { int64_t a = vJ(v, B), b = vJ(v, C); r = a < b ? -1 : (a > b ? 1 : 0); }
                else if (op == 0x2d || op == 0x2f) {
                    double a = (op == 0x2d) ? (double)vF(v, B) : vD(v, B);
                    double b = (op == 0x2d) ? (double)vF(v, C) : vD(v, C);
                    r = (isnan(a) || isnan(b)) ? -1 : (a < b ? -1 : (a > b ? 1 : 0));
                } else {
                    double a = (op == 0x2e) ? (double)vF(v, B) : vD(v, B);
                    double b = (op == 0x2e) ? (double)vF(v, C) : vD(v, C);
                    r = (isnan(a) || isnan(b)) ? 1 : (a < b ? -1 : (a > b ? 1 : 0));
                }
                wI(v, A, r);
                next = pc + 2;
                break;
            }
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
            case 0x96: case 0x97: case 0x98: case 0x99: case 0x9a: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff, C = (u1 >> 8) & 0xff;
                int32_t x = vI(v, B), y = vI(v, C);
                bool wrote = true;
                switch (op) {
                    case 0x90: x = wrapAdd32(x, y); break;
                    case 0x91: x = wrapSub32(x, y); break;
                    case 0x92: x = wrapMul32(x, y); break;
                    case 0x93: case 0x94: {
                        if (y == 0) {
                            wrote = false;
                            if (!failArith()) { done = true; result.exception = true; }
                        } else if (op == 0x93) x = dalvikDiv32(x, y);
                        else x = dalvikRem32(x, y);
                        break;
                    }
                    case 0x95: x &= y; break; case 0x96: x |= y; break; case 0x97: x ^= y; break;
                    case 0x98: x = (int32_t)((uint32_t)x << (y & 31)); break;
                    case 0x99: x = x >> (y & 31); break;
                    case 0x9a: x = (int32_t)((uint32_t)x >> (y & 31)); break;
                }
                if (wrote) wI(v, A, x);
                next = pc + 2;
                break;
            }
            case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f: case 0xa0:
            case 0xa1: case 0xa2: case 0xa3: case 0xa4: case 0xa5: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff, C = (u1 >> 8) & 0xff;
                int64_t x = vJ(v, B), y = vJ(v, C);
                bool wrote = true;
                switch (op) {
                    case 0x9b: x = wrapAdd64(x, y); break;
                    case 0x9c: x = wrapSub64(x, y); break;
                    case 0x9d: x = wrapMul64(x, y); break;
                    case 0x9e: case 0x9f: {
                        if (y == 0) {
                            wrote = false;
                            if (!failArith()) { done = true; result.exception = true; }
                        } else if (op == 0x9e) x = dalvikDiv64(x, y);
                        else x = dalvikRem64(x, y);
                        break;
                    }
                    case 0xa0: x &= y; break; case 0xa1: x |= y; break; case 0xa2: x ^= y; break;
                    case 0xa3: x = (int64_t)((uint64_t)x << (y & 63)); break;
                    case 0xa4: x = x >> (y & 63); break;
                    case 0xa5: x = (int64_t)((uint64_t)x >> (y & 63)); break;
                }
                if (wrote) wJ(v, A, x);
                next = pc + 2;
                break;
            }
            case 0xa6: case 0xa7: case 0xa8: case 0xa9: case 0xaa: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff, C = (u1 >> 8) & 0xff;
                float x = vF(v, B), y = vF(v, C);
                switch (op) {
                    case 0xa6: x += y; break; case 0xa7: x -= y; break;
                    case 0xa8: x *= y; break; case 0xa9: x /= y; break; case 0xaa: x = fmodf(x, y); break;
                }
                wF(v, A, x);
                next = pc + 2;
                break;
            }
            case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff, C = (u1 >> 8) & 0xff;
                double x = vD(v, B), y = vD(v, C);
                switch (op) {
                    case 0xab: x += y; break; case 0xac: x -= y; break;
                    case 0xad: x *= y; break; case 0xae: x /= y; break; case 0xaf: x = fmod(x, y); break;
                }
                wD(v, A, x);
                next = pc + 2;
                break;
            }

            case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a:
            case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff, C = (u1 >> 8) & 0xff;
                bool isGet = op < 0x4b;
                jarray arr = (jarray)vL(v, B);
                jsize idx = vI(v, C);
                if (!arr) {
                    throwJava(env, "java/lang/NullPointerException", "null array in aget/aput");
                    if (!routeException()) { done = true; result.exception = true; }
                    next = pc + 2;
                    break;
                }
                jsize alen = env->GetArrayLength(arr);
                if (idx < 0 || idx >= alen) {
                    char msg[96];
                    snprintf(msg, sizeof(msg),
                             "Internal error: array index %d out of bounds for length %d", idx, alen);
                    throwJava(env, "java/lang/ArrayIndexOutOfBoundsException", msg);
                    if (!routeException()) { done = true; result.exception = true; }
                    next = pc + 2;
                    break;
                }
                if (isGet) {
                    switch (op) {
                        case 0x44: {
                            if (arr) {
                                jclass ci = classOfDesc(env, "[I", 2);
                                if (ci && env->IsInstanceOf(arr, ci)) {
                                    jint x = 0; env->GetIntArrayRegion((jintArray)arr, idx, 1, &x); wI(v, A, x);
                                } else {
                                    jclass cf = classOfDesc(env, "[F", 2);
                                    if (cf && env->IsInstanceOf(arr, cf)) {
                                        jfloat x = 0; env->GetFloatArrayRegion((jfloatArray)arr, idx, 1, &x); wF(v, A, x);
                                    }
                                }
                            }
                            break;
                        }
                        case 0x45: {
                            if (arr) {
                                jclass cj = classOfDesc(env, "[J", 2);
                                if (cj && env->IsInstanceOf(arr, cj)) {
                                    jlong x = 0; env->GetLongArrayRegion((jlongArray)arr, idx, 1, &x); wJ(v, A, x);
                                } else {
                                    jclass cd = classOfDesc(env, "[D", 2);
                                    if (cd && env->IsInstanceOf(arr, cd)) {
                                        jdouble x = 0; env->GetDoubleArrayRegion((jdoubleArray)arr, idx, 1, &x); wD(v, A, x);
                                    }
                                }
                            }
                            break;
                        }
                        case 0x46: wL(v, A, arr ? env->GetObjectArrayElement((jobjectArray)arr, idx) : nullptr); break;
                        case 0x47: { jboolean x=0; if(arr) env->GetBooleanArrayRegion((jbooleanArray)arr,idx,1,&x); wI(v,A,x); break; }
                        case 0x48: { jbyte x=0; if(arr) env->GetByteArrayRegion((jbyteArray)arr,idx,1,&x); wI(v,A,x); break; }
                        case 0x49: { jchar x=0; if(arr) env->GetCharArrayRegion((jcharArray)arr,idx,1,&x); wI(v,A,x); break; }
                        case 0x4a: { jshort x=0; if(arr) env->GetShortArrayRegion((jshortArray)arr,idx,1,&x); wI(v,A,x); break; }
                    }
                } else {
                    switch (op) {
                        case 0x4b: {
                            if (arr) {
                                jclass ci = classOfDesc(env, "[I", 2);
                                if (ci && env->IsInstanceOf(arr, ci)) {
                                    jint x = vI(v, A); env->SetIntArrayRegion((jintArray)arr, idx, 1, &x);
                                } else {
                                    jclass cf = classOfDesc(env, "[F", 2);
                                    if (cf && env->IsInstanceOf(arr, cf)) {
                                        jfloat x = vF(v, A); env->SetFloatArrayRegion((jfloatArray)arr, idx, 1, &x);
                                    }
                                }
                            }
                            break;
                        }
                        case 0x4c: {
                            if (arr) {
                                jclass cj = classOfDesc(env, "[J", 2);
                                if (cj && env->IsInstanceOf(arr, cj)) {
                                    jlong x = vJ(v, A); env->SetLongArrayRegion((jlongArray)arr, idx, 1, &x);
                                } else {
                                    jclass cd = classOfDesc(env, "[D", 2);
                                    if (cd && env->IsInstanceOf(arr, cd)) {
                                        jdouble x = vD(v, A); env->SetDoubleArrayRegion((jdoubleArray)arr, idx, 1, &x);
                                    }
                                }
                            }
                            break;
                        }
                        case 0x4d: if(arr) env->SetObjectArrayElement((jobjectArray)arr, idx, vL(v,A)); break;
                        case 0x4e: if(arr) { jboolean x=(jboolean)vI(v,A); env->SetBooleanArrayRegion((jbooleanArray)arr,idx,1,&x); } break;
                        case 0x4f: if(arr) { jbyte x=(jbyte)vI(v,A); env->SetByteArrayRegion((jbyteArray)arr,idx,1,&x); } break;
                        case 0x50: if(arr) { jchar x=(jchar)vI(v,A); env->SetCharArrayRegion((jcharArray)arr,idx,1,&x); } break;
                        case 0x51: if(arr) { jshort x=(jshort)vI(v,A); env->SetShortArrayRegion((jshortArray)arr,idx,1,&x); } break;
                    }
                }
                if (!routeException()) { done = true; result.exception = true; }
                next = pc + 2;
                break;
            }

            case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
            case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                bool isGet = op < 0x59;
                if (!doFieldOp(env, file, v, v, fetch16(insns, pc + 1), false, isGet, A, B, pc)) {
                    if (!failSilent("Internal error: instance field op failed")) { done = true; result.exception = true; }
                }
                next = pc + 2;
                break;
            }

            case 0x20: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                jobject obj = vL(v, B);
                jclass c = file->classOfType(env, fetch16(insns, pc + 1));
                if (!c) {
                    if (!failSilent("Internal error: instance-of: unresolved type")) {
                        done = true; result.exception = true;
                    }
                }
                wI(v, A, (obj && c && env->IsInstanceOf(obj, c)) ? 1 : 0);
                next = pc + 2;
                break;
            }

            case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: {
                int A = (code >> 12) & 0xf;
                int G = (code >> 8) & 0xf;
                uint16_t idx = fetch16(insns, pc + 1);
                uint16_t u2 = fetch16(insns, pc + 2);
                int raw[5] = { u2 & 0xf, (u2 >> 4) & 0xf, (u2 >> 8) & 0xf, (u2 >> 12) & 0xf, G };
                int kind = op == 0x6e ? INVOKE_VIRTUAL : op == 0x6f ? INVOKE_SUPER :
                           op == 0x70 ? INVOKE_DIRECT : op == 0x71 ? INVOKE_STATIC : INVOKE_INTERFACE;
                int regs[5];
                int nregs = 0;
                {
                    const char *tshorty = file->getMethodShorty(idx);
                    int wi = 0;
                    if (kind != INVOKE_STATIC && wi < 5) {
                        regs[nregs++] = raw[wi++];
                    }
                    if (tshorty) {
                        int np = (int)strlen(tshorty) - 1;
                        for (int i = 0; i < np && nregs < 5; i++) {
                            if (wi >= 5) break;
                            regs[nregs++] = raw[wi];
                            wi += (tshorty[i + 1] == 'J' || tshorty[i + 1] == 'D') ? 2 : 1;
                        }
                        int expect = (kind != INVOKE_STATIC ? 1 : 0);
                        for (int i = 0; i < np; i++) {
                            expect += (tshorty[i + 1] == 'J' || tshorty[i + 1] == 'D') ? 2 : 1;
                        }
                        if (A != expect && !g_logged35cWordMismatch) {
                            g_logged35cWordMismatch = true;
                            LOGE("vm invoke width mismatch: A=%d shorty=%d for %s.%s",
                                 A, expect,
                                 file->getMethodClass((int)idx) ? file->getMethodClass((int)idx) : "?",
                                 file->getMethodName((int)idx) ? file->getMethodName((int)idx) : "?");
                        }
                    } else {
                        while (nregs < 5 && wi < 5) regs[nregs++] = raw[wi++];
                    }
                }
                if (nregs < 1) nregs = 1;
                memset(&lastResult, 0, sizeof(lastResult));
                if (!doInvoke(env, file, v, idx, kind, regs, nregs, &lastResult, pc, m)) {
                    if (!routeException()) {
                        dumpVmState("invoke threw, uncaught", idx);
                        done = true; result.exception = true;
                    }
                }
                {
                    const char *tshorty = file->getMethodShorty(idx);
                    if (tshorty && tshorty[0] == 'L') {
                        lastResultMethodId = (int)idx;
                        pendingResultPc = pc;
                        pendingResultReg = -1;
                    }
                }
                next = pc + 3;
                break;
            }

            case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                int A = (code >> 8) & 0xff;
                uint16_t idx = fetch16(insns, pc + 1);
                int C = fetch16(insns, pc + 2);
                int kind = op == 0x74 ? INVOKE_VIRTUAL : op == 0x75 ? INVOKE_SUPER :
                           op == 0x76 ? INVOKE_DIRECT : op == 0x77 ? INVOKE_STATIC : INVOKE_INTERFACE;
                std::vector<int> regs;
                const char *rshorty = file->getMethodShorty(idx);
                if (!rshorty) {
                    regs.resize(A);
                    for (int i = 0; i < A; i++) regs[i] = C + i;
                } else {
                    int rnparams = (int)strlen(rshorty) - 1;
                    if (kind != INVOKE_STATIC) { regs.push_back(C); }
                    int reg = C + (kind != INVOKE_STATIC ? 1 : 0);
                    int words = kind != INVOKE_STATIC ? 1 : 0;
                    for (int i = 0; i < rnparams && words < A; i++) {
                        char t = rshorty[i + 1];
                        int w = (t == 'J' || t == 'D') ? 2 : 1;
                        regs.push_back(reg);
                        reg += w;
                        words += w;
                    }
                }
                memset(&lastResult, 0, sizeof(lastResult));
                if (!doInvoke(env, file, v, idx, kind, regs.data(), (int)regs.size(), &lastResult, pc, m)) {
                    if (!routeException()) {
                        dumpVmState("invoke threw, uncaught", idx);
                        done = true; result.exception = true;
                    }
                }
                {
                    const char *tshorty = file->getMethodShorty(idx);
                    if (tshorty && tshorty[0] == 'L') {
                        lastResultMethodId = (int)idx;
                        pendingResultPc = pc;
                        pendingResultReg = -1;
                    }
                }
                next = pc + 3;
                break;
            }

            case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
                int A = (code >> 8) & 0xf, B = (code >> 12) & 0xf;
                int16_t lit = (int16_t)fetch16(insns, pc + 1);
                int32_t x = vI(v, B);
                bool wrote = true;
                switch (op) {
                    case 0xd0: x = wrapAdd32(x, lit); break;
                    case 0xd1: x = wrapSub32(lit, x); break;
                    case 0xd2: x = wrapMul32(x, lit); break;
                    case 0xd3: case 0xd4: {
                        if (lit == 0) {
                            wrote = false;
                            if (!failArith()) { done = true; result.exception = true; }
                        } else if (op == 0xd3) x = dalvikDiv32(x, lit);
                        else x = dalvikRem32(x, lit);
                        break;
                    }
                    case 0xd5: x &= lit; break; case 0xd6: x |= lit; break; case 0xd7: x ^= lit; break;
                }
                if (wrote) wI(v, A, x);
                next = pc + 2;
                break;
            }


            case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd: case 0xde: case 0xdf:
            case 0xe0: case 0xe1: case 0xe2: {
                int A = (code >> 8) & 0xff;
                uint16_t u1 = fetch16(insns, pc + 1);
                int B = u1 & 0xff;
                int8_t lit = (int8_t)((u1 >> 8) & 0xff);
                int32_t x = vI(v, B);
                bool wrote = true;
                switch (op) {
                    case 0xd8: x = wrapAdd32(x, lit); break;
                    case 0xd9: x = wrapSub32(lit, x); break;
                    case 0xda: x = wrapMul32(x, lit); break;
                    case 0xdb: case 0xdc: {
                        if (lit == 0) {
                            wrote = false;
                            if (!failArith()) { done = true; result.exception = true; }
                        } else if (op == 0xdb) x = dalvikDiv32(x, lit);
                        else x = dalvikRem32(x, lit);
                        break;
                    }
                    case 0xdd: x &= lit; break; case 0xde: x |= lit; break; case 0xdf: x ^= lit; break;
                    case 0xe0: x = (int32_t)((uint32_t)x << (lit & 31)); break;
                    case 0xe1: x = x >> (lit & 31); break;
                    case 0xe2: x = (int32_t)((uint32_t)x >> (lit & 31)); break;
                }
                if (wrote) wI(v, A, x);
                next = pc + 2;
                break;
            }

            case 0x24: {
                int A = (code >> 12) & 0xf;
                int G = (code >> 8) & 0xf;
                uint16_t idx = fetch16(insns, pc + 1);
                uint16_t u2 = fetch16(insns, pc + 2);
                int regs[5] = { u2 & 0xf, (u2 >> 4) & 0xf, (u2 >> 8) & 0xf, (u2 >> 12) & 0xf, G };
                const char *desc = file->getTypeDescriptor(idx);
                const size_t dl = desc ? strlen(desc) : 0;
                const bool descOk = desc && desc[0] == '[' && A <= 5;
                if (!descOk &&
                    !failSilent("Internal error: filled-new-array: unresolved element type")) {
                    done = true; result.exception = true;
                }
                bool rangeOk = descOk;
                for (int i = 0; rangeOk && i < A; i++)
                    if (regs[i] < 0 || regs[i] >= m->regs) rangeOk = false;
                if (descOk && !rangeOk &&
                    !failSilent("Internal error: filled-new-array: register range out of frame")) {
                    done = true; result.exception = true;
                }
                jobject arr = nullptr;
                if (descOk && rangeOk) {
                    int stride = (desc[1] == 'J' || desc[1] == 'D') ? 2 : 1;
                    jsize size = A / stride;
                    if (desc[1] == '[' && dl >= 3) {
                        std::string elem(desc + 1, dl - 1);
                        jclass c = env->FindClass(elem.c_str());
                        arr = c ? env->NewObjectArray(size, c, nullptr) : nullptr;
                    } else if (desc[1] == 'L' && dl >= 3) {
                        std::string elem(desc + 2, dl - 3);
                        jclass c = env->FindClass(elem.c_str());
                        arr = c ? env->NewObjectArray(size, c, nullptr) : nullptr;
                    } else {
                        switch (desc[1]) {
                            case 'Z': arr = env->NewBooleanArray(size); break;
                            case 'B': arr = env->NewByteArray(size); break;
                            case 'S': arr = env->NewShortArray(size); break;
                            case 'C': arr = env->NewCharArray(size); break;
                            case 'I': arr = env->NewIntArray(size); break;
                            case 'J': arr = env->NewLongArray(size); break;
                            case 'F': arr = env->NewFloatArray(size); break;
                            case 'D': arr = env->NewDoubleArray(size); break;
                        }
                    }
                    if (arr) {
                        for (int i = 0; i < size; i++) {
                            jvalue jv; memset(&jv, 0, sizeof(jv));
                            if (desc[1] == 'L' || desc[1] == '[') { jv.l = vL(v, regs[i * stride]); env->SetObjectArrayElement((jobjectArray)arr, i, jv.l); }
                            else {
                                switch (desc[1]) {
                                    case 'I': { jint x = vI(v, regs[i * stride]); env->SetIntArrayRegion((jintArray)arr, i, 1, &x); } break;
                                    case 'J': { jlong x = vJ(v, regs[i * stride]); env->SetLongArrayRegion((jlongArray)arr, i, 1, &x); } break;
                                    case 'Z': { jboolean x = (jboolean)vI(v, regs[i * stride]); env->SetBooleanArrayRegion((jbooleanArray)arr, i, 1, &x); } break;
                                    case 'B': { jbyte x = (jbyte)vI(v, regs[i * stride]); env->SetByteArrayRegion((jbyteArray)arr, i, 1, &x); } break;
                                    case 'S': { jshort x = (jshort)vI(v, regs[i * stride]); env->SetShortArrayRegion((jshortArray)arr, i, 1, &x); } break;
                                    case 'C': { jchar x = (jchar)vI(v, regs[i * stride]); env->SetCharArrayRegion((jcharArray)arr, i, 1, &x); } break;
                                    case 'F': { jfloat x = vF(v, regs[i * stride]); env->SetFloatArrayRegion((jfloatArray)arr, i, 1, &x); } break;
                                    case 'D': { jdouble x = vD(v, regs[i * stride]); env->SetDoubleArrayRegion((jdoubleArray)arr, i, 1, &x); } break;
                                }
                            }
                        }
                    }
                }
                lastResult.l = arr;
                if (!routeException()) { done = true; result.exception = true; }
                next = pc + 3;
                break;
            }

            case 0x25: {
                int A = (code >> 8) & 0xff;
                uint16_t idx = fetch16(insns, pc + 1);
                int C = fetch16(insns, pc + 2);
                const char *desc = file->getTypeDescriptor(idx);
                const size_t dl = desc ? strlen(desc) : 0;
                const bool descOk = desc && desc[0] == '[';
                if (!descOk &&
                    !failSilent("Internal error: filled-new-array/range: unresolved element type")) {
                    done = true; result.exception = true;
                }
                const bool rangeOk = A == 0 || C + A <= m->regs;
                if (descOk && !rangeOk &&
                    !failSilent("Internal error: filled-new-array/range: register range out of frame")) {
                    done = true; result.exception = true;
                }
                jobject arr = nullptr;
                if (descOk && rangeOk) {
                    int stride = (desc[1] == 'J' || desc[1] == 'D') ? 2 : 1;
                    jsize size = A / stride;
                    if (desc[1] == '[' && dl >= 3) {
                        std::string elem(desc + 1, dl - 1);
                        jclass c = env->FindClass(elem.c_str());
                        arr = c ? env->NewObjectArray(size, c, nullptr) : nullptr;
                    } else if (desc[1] == 'L' && dl >= 3) {
                        std::string elem(desc + 2, dl - 3);
                        jclass c = env->FindClass(elem.c_str());
                        arr = c ? env->NewObjectArray(size, c, nullptr) : nullptr;
                    } else {
                        switch (desc[1]) {
                            case 'Z': arr = env->NewBooleanArray(size); break;
                            case 'B': arr = env->NewByteArray(size); break;
                            case 'S': arr = env->NewShortArray(size); break;
                            case 'C': arr = env->NewCharArray(size); break;
                            case 'I': arr = env->NewIntArray(size); break;
                            case 'J': arr = env->NewLongArray(size); break;
                            case 'F': arr = env->NewFloatArray(size); break;
                            case 'D': arr = env->NewDoubleArray(size); break;
                        }
                    }
                    if (arr) {
                        for (int i = 0; i < size; i++) {
                            if (desc[1] == 'L' || desc[1] == '[') { env->SetObjectArrayElement((jobjectArray)arr, i, vL(v, C + i * stride)); }
                            else {
                                switch (desc[1]) {
                                    case 'I': { jint x = vI(v, C + i * stride); env->SetIntArrayRegion((jintArray)arr, i, 1, &x); } break;
                                    case 'J': { jlong x = vJ(v, C + i * stride); env->SetLongArrayRegion((jlongArray)arr, i, 1, &x); } break;
                                    case 'Z': { jboolean x = (jboolean)vI(v, C + i * stride); env->SetBooleanArrayRegion((jbooleanArray)arr, i, 1, &x); } break;
                                    case 'B': { jbyte x = (jbyte)vI(v, C + i * stride); env->SetByteArrayRegion((jbyteArray)arr, i, 1, &x); } break;
                                    case 'S': { jshort x = (jshort)vI(v, C + i * stride); env->SetShortArrayRegion((jshortArray)arr, i, 1, &x); } break;
                                    case 'C': { jchar x = (jchar)vI(v, C + i * stride); env->SetCharArrayRegion((jcharArray)arr, i, 1, &x); } break;
                                    case 'F': { jfloat x = vF(v, C + i * stride); env->SetFloatArrayRegion((jfloatArray)arr, i, 1, &x); } break;
                                    case 'D': { jdouble x = vD(v, C + i * stride); env->SetDoubleArrayRegion((jdoubleArray)arr, i, 1, &x); } break;
                                }
                            }
                        }
                    }
                }
                lastResult.l = arr;
                if (!routeException()) { done = true; result.exception = true; }
                next = pc + 3;
                break;
            }

            default:
                dumpVmState("unsupported opcode");
                LOGE("unsupported opcode 0x%02x at pc=%d", op, pc);
                throwJava(env, "java/lang/InternalError",
                          "Internal error: unsupported opcode");
                done = true;
                result.exception = true;
                break;
        }
        if (handlerPc >= 0) {
            pc = handlerPc;
            handlerPc = -1;
        } else {
            pc = next;
        }
    }

    if (!done && !hasPendingException(env)) {
        dumpVmState("fell off the end of the method without returning");
        const char *fCls = file->getMethodClass(m->method_id_idx);
        const char *fNm = file->getMethodName(m->method_id_idx);
        LOGE("vm-exit: %s.%s at pc=%d without a return (size=%d)",
             fCls ? fCls : "?", fNm ? fNm : "?", pc, m->insns_size);
        jclass ie = env->FindClass("java/lang/InternalError");
        if (ie) {
            env->ThrowNew(ie, "Internal error: method fell off the end without returning");
            env->DeleteLocalRef(ie);
        }
        result.exception = true;
    }

    /* JNI MonitorEnter is not automatically balanced when this native
     * interpreter frame unwinds through an exception. Restore any exception,
     * release every monitor acquired by this frame in reverse order, then
     * rethrow the original exception. */
    if (pendingThrowable && !hasPendingException(env)) {
        env->Throw((jthrowable)pendingThrowable);
        pendingThrowable = nullptr;
    }
    jobject pendingOnExit = takePendingException(env);
    for (auto it = enteredMonitors.rbegin(); it != enteredMonitors.rend(); ++it) {
        env->MonitorExit(*it);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    enteredMonitors.clear();
    if (pendingOnExit) rethrow(env, pendingOnExit);

    char rt = shorty ? shorty[0] : 'V';
    delete[] regs64;
    if (rt == 'L') {
        result.value.l = env->PopLocalFrame(result.value.l);
    } else {
        env->PopLocalFrame(nullptr);
    }
    return result;
}
