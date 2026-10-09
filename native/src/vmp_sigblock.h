#ifndef VMP_SIGBLOCK_H
#define VMP_SIGBLOCK_H

#include <jni.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Extracts the SHA-256 digest of the signer certificate from the installed
 * APK's APK Signing Block (v2 preferred, with v3/v3.1 fallback). This
 * structural helper is separate from vmpVerifyApkSignature, which performs the
 * cryptographic signature and content-digest verification used by the runtime.
 *
 * Returns true and fills out[32] on success. On failure, noSigBlock identifies
 * an absent or unrecognised block (or an unavailable hash self-test); callers
 * must still fail closed when the certificate cannot be authenticated.
 *
 * The reason value identifies the failure category documented below. The
 * function does not emit log messages.
 */
bool vmpReadFileCertDigest(JNIEnv *env, jobject ctx, uint8_t out[32],
                           bool *noSigBlock, int *reason, uint32_t *dbg);

/**
 * Cryptographically verifies the installed APK's v2/v3 signature and the
 * official chunked APK content digest. The returned certificate digest is
 * from the verified signer certificate. Unsupported v3.1/algorithm cases
 * fail closed rather than falling back to certificate-only acceptance.
 */
bool vmpVerifyApkSignature(JNIEnv *env, jobject ctx, uint8_t certDigest[32],
                           bool *noSigBlock, int *reason);

/**
 * SHA-256 over an arbitrary buffer, shared with the signing-block parser
 * (one implementation, one self-verified constant table). Returns false if
 * the constant self-test has not passed - callers MUST fail closed on false.
 */
bool vmpSha256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * HMAC-SHA256 (envelope v4: authenticate ciphertext BEFORE decrypt/parse).
 * Fails closed unless this TU's RFC-4231 self-test passed; callers must refuse
 * the blob on false.
 */
bool vmpHmacSha256(const uint8_t *key, size_t klen,
                   const uint8_t *msg, size_t mlen, uint8_t out[32]);

/* Failure reasons shared by the signing-block and signature-verification APIs
 * (0 = success):
 *  1  SHA-256 self-test failed or is unavailable
 *  2  file is smaller than the minimum ZIP size
 *  3  EOCD signature is absent from the tail window
 *  4  central-directory offset is invalid or uses ZIP64
 *  5  APK Signing Block magic is absent
 *  6  signing-block bounds or size fields are invalid
 *  7  no supported v2/v3/v3.1 signing pair is present
 *  8  signer or certificate data is malformed
 * 10  source APK cannot be opened or mapped
 * 11  SHA-256 is not ready at entry
 * 12  stat(path) and fstat(fd) identify different files
 * 14  signature verification failed
 * 15  unsupported or invalid signer attributes
 * 16  APK content digest mismatch
 */

#endif
