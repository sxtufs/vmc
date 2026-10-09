#!/usr/bin/env python3
"""Generate self-verified SHA-256 and HMAC-SHA256 constants as a C header.

The tables use arbitrary-precision integer math and are checked against
Python's hashlib and hmac implementations before the header is written. Usage:

    python3 gen_consts.py <output-header-path>
"""
import hashlib
import math
import sys

PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
]


def icbrt(n):
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


# First 32 bits of the fractional parts: frac(root(p))*2^32 is the low word
# of root(p*2^(32*root_degree)) under exact integer roots.
K = [icbrt(p << 96) & 0xFFFFFFFF for p in PRIMES]        # cube roots, 64
H0 = [math.isqrt(p << 64) & 0xFFFFFFFF for p in PRIMES[:8]]  # sq roots, 8


def sha256_with(msg, k, h0):
    def rotr(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    h = list(h0)
    m = bytearray(msg)
    m.append(0x80)
    while len(m) % 64 != 56:
        m.append(0)
    m += (8 * len(msg)).to_bytes(8, "big")
    w = [0] * 64
    for off in range(0, len(m), 64):
        for i in range(16):
            w[i] = int.from_bytes(m[off + 4 * i: off + 4 * i + 4], "big")
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            t1 = (hh + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & 0xFFFFFFFF
            hh, g, f = g, f, e
            e = (d + t1) & 0xFFFFFFFF
            d, c, b = c, b, a
            a = (t1 + t2) & 0xFFFFFFFF
        for i, v in enumerate((a, b, c, d, e, f, g, hh)):
            h[i] = (h[i] + v) & 0xFFFFFFFF
    return b"".join(x.to_bytes(4, "big") for x in h)


def verified_words(vec):
    """Check the generated tables against hashlib and return digest words."""
    hexd = hashlib.sha256(vec).hexdigest()
    if sha256_with(vec, K, H0).hex() != hexd:
        print("FATAL: generated tables disagree with hashlib on %r" % vec,
              file=sys.stderr)
        sys.exit(1)
    raw = bytes.fromhex(hexd)
    return [int.from_bytes(raw[4 * i:4 * i + 4], "big") for i in range(8)]


TEST_EMPTY = verified_words(b"")
TEST_ABC = verified_words(b"abc")


# HMAC-SHA256 known-answer tests for the envelope v4 authentication path.
# The standard-library result verifies the pure-Python implementation before
# the generated expectations are emitted.
def hmac256_pure(key, msg):
    blk = 64
    if len(key) > blk:
        key = sha256_with(key, K, H0)
    key = key + b"\x00" * (blk - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5c for b in key)
    return sha256_with(opad + sha256_with(ipad + msg, K, H0), K, H0)


def verified_hmac(tag, key, msg):
    import hmac as _hmac
    ref = _hmac.new(key, msg, hashlib.sha256).digest()
    if hmac256_pure(key, msg) != ref:
        print("FATAL: pure-python HMAC (%s) disagrees with stdlib" % tag,
              file=sys.stderr)
        sys.exit(1)
    return ref


# RFC 4231 case 2 (short key) and case 6 (>64-byte key: the hash-the-key
# branch). Cases 1-5 differ only in inputs already covered by these two
# key-path branches.
HK1_KEY, HK1_MSG = bytes([0x0b]) * 20, b"Hi There"
HK2_KEY = bytes([0xaa]) * 131
HK2_MSG = b"Test Using Larger Than Block-Size Key - Hash Key First"
HMAC1, HMAC2 = verified_hmac("case2", HK1_KEY, HK1_MSG), verified_hmac("case6", HK2_KEY, HK2_MSG)


def fmt_b(arr):
    return "\n".join(
        "    " + ", ".join("0x%02x" % v for v in arr[i:i + 8]) + ","
        for i in range(0, len(arr), 8))


def words(b):
    return [int.from_bytes(b[4 * i:4 * i + 4], "big") for i in range(8)]


def fmt(arr):
    return "\n".join(
        "    " + ", ".join("0x%08xu" % v for v in arr[i:i + 4]) + ","
        for i in range(0, len(arr), 4))


HEADER = """// GENERATED at build time by native/gen_consts.py - DO NOT EDIT, DO NOT
// COMMIT (build directory artifact). Exact FIPS 180-4 SHA-256 constants,
// derived with pure integer arithmetic and re-verified against hashlib on
// the "" and "abc" vectors before this file was written. Tripwire: the
// runtime self-test in vmp_sigblock.cpp (failure reason r=1).
#ifndef VMP_SHA256_CONSTS_H
#define VMP_SHA256_CONSTS_H

#include <stdint.h>

static const uint32_t VMP_SHA_K[64] = {
%s
};

static const uint32_t VMP_SHA_H0[8] = {
%s
};

/* Expected self-test vectors, extracted from hashlib here (never typed by
   hand): digest("") and digest("abc"). */
static const uint32_t VMP_SHA_TEST_EMPTY[8] = {
%s
};

static const uint32_t VMP_SHA_TEST_ABC[8] = {
%s
};

/* HMAC-SHA256 KATs, RFC 4231 cases 2 and 6. Keys/messages are inputs;
   the T* expectations below were produced by python's hmac stdlib, with
   the pure-python HMAC over the tables above verified against it first.
   Tripwire: vmpHmacSha256 self-test (a failure returns false from
   vmpHmacSha256 and vmpDecodeBlob refuses the blob; no sigblock reason
   code is involved).

   Byte arrays are UNSIZED deliberately: sizeof over a complete [] array keeps
   the runtime self-test honest without restating a length by hand. */
static const uint8_t VMP_HMAC_K1[] = {
%s
};
static const uint8_t VMP_HMAC_M1[] = {
%s
};
static const uint32_t VMP_HMAC_T1[8] = {
%s
};
static const uint8_t VMP_HMAC_K2[] = {
%s
};
static const uint8_t VMP_HMAC_M2[] = {
%s
};
static const uint32_t VMP_HMAC_T2[8] = {
%s
};

#endif // VMP_SHA256_CONSTS_H
""" % (fmt(K), fmt(H0), fmt(TEST_EMPTY), fmt(TEST_ABC),
     fmt_b(HK1_KEY), fmt_b(HK1_MSG), fmt(words(HMAC1)),
     fmt_b(HK2_KEY), fmt_b(HK2_MSG), fmt(words(HMAC2)))

if len(sys.argv) != 2:
    print("usage: gen_consts.py <output-header>", file=sys.stderr)
    sys.exit(2)

with open(sys.argv[1], "w") as fh:
    fh.write(HEADER)
print("vmp_sha256_consts.h written (self-verified against hashlib)")
