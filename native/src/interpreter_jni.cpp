#include "interpreter_jni.h"

bool hasPendingException(JNIEnv *env) {
    return env->ExceptionCheck();
}

jobject takePendingException(JNIEnv *env) {
    if (!env->ExceptionCheck()) return nullptr;
    jthrowable throwable = env->ExceptionOccurred();
    env->ExceptionClear();
    return throwable;
}

void rethrow(JNIEnv *env, jobject throwable) {
    if (throwable) {
        env->Throw((jthrowable)throwable);
        env->DeleteLocalRef(throwable);
    }
}

void throwJava(JNIEnv *env, const char *klass, const char *msg) {
    jclass exceptionClass = env->FindClass(klass);
    if (!exceptionClass) return;
    env->ThrowNew(exceptionClass, msg);
    env->DeleteLocalRef(exceptionClass);
}

int findCatchHandler(const uint32_t *tries, int triesSize, int pc,
                    jobject throwable, JNIEnv *env, VmpFile *file) {
    if (!tries || triesSize <= 0) return -1;
    for (int i = 0; i < triesSize; i++) {
        uint32_t startAddr = tries[i * 4 + 0];
        uint32_t insnCount = tries[i * 4 + 1];
        if (pc >= (int)startAddr && pc < (int)(startAddr + insnCount)) {
            uint32_t typeIdx = tries[i * 4 + 2];
            uint32_t handlerAddr = tries[i * 4 + 3];
            if (typeIdx == 0xffffffffu) return (int)handlerAddr;
            jclass catchClass = file ? file->classOfType(env, typeIdx) : nullptr;
            if (catchClass && throwable && env->IsInstanceOf(throwable, catchClass)) {
                return (int)handlerAddr;
            }
        }
    }
    return -1;
}
