#pragma once
/* Minimal host-only JNI declarations for the fuzz harness. */
#include <stdint.h>

typedef int32_t jint;
typedef int64_t jlong;
typedef uint16_t jchar;
typedef int16_t jshort;
typedef uint8_t jboolean;
typedef int8_t jbyte;
typedef int32_t jsize;
typedef float jfloat;
typedef double jdouble;
#define JNI_TRUE 1
#define JNI_FALSE 0
#define JNI_OK 0
#define JNI_VERSION_1_4 0x00010400
#define JNI_VERSION_1_6 0x00010600

typedef void *jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jthrowable;
typedef jobject jbyteArray;
typedef void *jmethodID;
typedef void *jfieldID;

struct JNIEnv_ {
    jclass FindClass(const char *) const { return nullptr; }
    jobject NewGlobalRef(jobject o) const { return o; }
    void DeleteLocalRef(jobject) const { }
    jmethodID GetMethodID(jclass, const char *, const char *) const { return nullptr; }
    jmethodID GetStaticMethodID(jclass, const char *, const char *) const { return nullptr; }
    jfieldID GetFieldID(jclass, const char *, const char *) const { return nullptr; }
    jfieldID GetStaticFieldID(jclass, const char *, const char *) const { return nullptr; }
    bool ExceptionCheck() const { return false; }
    void ExceptionClear() { }
};
typedef JNIEnv_ JNIEnv;
