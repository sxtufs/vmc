#ifndef VMP_APK_VERIFY_H
#define VMP_APK_VERIFY_H

#include <jni.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Verify the installed APK's v2/v3 cryptographic signature and APK content
 * digest. The returned certificate digest is from the verified signer, not
 * merely from an untrusted APK Signing Block parse.
 *
 * v3 is preferred on Android P+ when present; v2 is used only when v3 is
 * absent. SDK-range signers outside the current platform are ignored. This
 * verifier intentionally rejects v3 proof-of-rotation attributes and v3.1
 * blocks until lineage verification is implemented; unsupported signing
 * schemes/algorithms fail closed.
 */
bool vmpVerifyApkSignature(JNIEnv *env, jobject ctx, uint8_t certDigest[32],
                           bool *noSigBlock, int *reason);

#endif
