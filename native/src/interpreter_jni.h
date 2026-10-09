#ifndef VMP_INTERPRETER_JNI_H
#define VMP_INTERPRETER_JNI_H

#include <jni.h>
#include "vmp_file.h"

bool hasPendingException(JNIEnv *env);
jobject takePendingException(JNIEnv *env);
void rethrow(JNIEnv *env, jobject throwable);
void throwJava(JNIEnv *env, const char *klass, const char *msg);

int findCatchHandler(const uint32_t *tries, int triesSize, int pc,
                    jobject throwable, JNIEnv *env, VmpFile *file);

#endif // VMP_INTERPRETER_JNI_H
