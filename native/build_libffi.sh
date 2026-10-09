#!/usr/bin/env bash

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <NDK_ROOT>" >&2
    exit 1
fi

NDK_ROOT="$(cd "$1" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/libffi"
SRC_DIR="${WORK_DIR}/src"
API_LEVEL=21

if [ ! -d "${NDK_ROOT}/toolchains/llvm/prebuilt" ]; then
    echo "NDK_ROOT does not look like a valid NDK (no toolchains/llvm/prebuilt): ${NDK_ROOT}" >&2
    exit 1
fi

HOST_TAG=""
for tag in linux-x86_64 darwin-x86_64 windows-x86_64; do
    if [ -d "${NDK_ROOT}/toolchains/llvm/prebuilt/${tag}" ]; then
        HOST_TAG="${tag}"
        break
    fi
done
if [ -z "${HOST_TAG}" ]; then
    echo "Unsupported NDK host toolchain" >&2
    exit 1
fi
TOOLCHAIN="${NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_TAG}"
echo "Using NDK toolchain: ${TOOLCHAIN}"

LIBFFI_TARBALL="libffi-3.8.0.tar.gz"
LIBFFI_URL="https://github.com/libffi/libffi/releases/download/v3.8.0/${LIBFFI_TARBALL}"
LIBFFI_EXPECTED_SHA256="${LIBFFI_SHA256:-7da3e2d9a171eb0a038f592ecad3ff2bb2550f3496d87b3b29ad0cf4430c0db4}"

mkdir -p "${SRC_DIR}"
cd "${SRC_DIR}"

if [ ! -f "${LIBFFI_TARBALL}" ]; then
    echo "Downloading libffi 3.8.0..."
    curl -fL -o "${LIBFFI_TARBALL}.part" "${LIBFFI_URL}"
    mv "${LIBFFI_TARBALL}.part" "${LIBFFI_TARBALL}"
fi

if [ "${LIBFFI_SKIP_VERIFY:-}" = "1" ]; then
    echo "WARNING: LIBFFI_SKIP_VERIFY=1 - building against an UNVERIFIED libffi." >&2
else
    if command -v sha256sum >/dev/null 2>&1; then SUM_TOOL="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then SUM_TOOL="shasum -a 256"
    else
        echo "Neither sha256sum nor shasum found; refusing to build unverified." >&2
        exit 1
    fi
    LIBFFI_ACTUAL="$(${SUM_TOOL} "${LIBFFI_TARBALL}" | awk '{print $1}')"
    if [ "${LIBFFI_ACTUAL}" != "${LIBFFI_EXPECTED_SHA256}" ]; then
        echo "libffi tarball checksum MISMATCH - refusing to build." >&2
        echo "  expected ${LIBFFI_EXPECTED_SHA256}" >&2
        echo "  actual   ${LIBFFI_ACTUAL}" >&2
        echo "If you are bumping the version, update the pinned digest (or pass" >&2
        echo "LIBFFI_SHA256=...) from a source you trust, then delete" >&2
        echo "  ${SRC_DIR}/${LIBFFI_TARBALL}  and  ${SRC_DIR}/libffi-3.8.0"
        exit 1
    fi
    echo "libffi tarball verified: ${LIBFFI_ACTUAL}"
fi

if [ ! -d libffi-3.8.0 ]; then
    tar xzf "${LIBFFI_TARBALL}"
fi

cd libffi-3.8.0

build_abi() {
    local ABI="$1"
    local TRIPLE="$2"
    local INSTALL="${WORK_DIR}/install/${ABI}"

    echo "============================================================"
    echo "Building libffi for ${ABI} (${TRIPLE})"
    echo "============================================================"
    local CC="${TOOLCHAIN}/bin/${TRIPLE}${API_LEVEL}-clang"
    local AR="${TOOLCHAIN}/bin/llvm-ar"
    local RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"

    if [ ! -x "${CC}" ]; then
        echo "Missing compiler: ${CC}" >&2
        exit 1
    fi

    rm -rf "build-${ABI}"
    mkdir -p "build-${ABI}"
    cd "build-${ABI}"

    BP=""
    case "${TRIPLE}" in aarch64-*) BP="-mbranch-protection=standard" ;; esac
    CC="${CC}" \
    AR="${AR}" \
    RANLIB="${RANLIB}" \
    CFLAGS="-O2 -fPIC ${BP} --sysroot=${TOOLCHAIN}/sysroot -D__ANDROID_API__=${API_LEVEL} -Wno-implicit-function-declaration" \
    ../configure \
        --host="${TRIPLE}" \
        --prefix="${INSTALL}" \
        --enable-static \
        --disable-shared \
        --disable-docs \
        --disable-multi-os-directory \
        --disable-dependency-tracking

    make -j"$(nproc 2>/dev/null || echo 4)"
    make install
    cd ..
}

triple_for() {
    case "$1" in
        arm64-v8a)   echo "aarch64-linux-android" ;;
        armeabi-v7a) echo "armv7a-linux-androideabi" ;;
        x86_64)      echo "x86_64-linux-android" ;;
        x86)         echo "i686-linux-android" ;;
        *)           return 1 ;;
    esac
}

ABIS="${LIBFFI_ABIS:-arm64-v8a armeabi-v7a x86_64 x86}"

for ABI in ${ABIS}; do
    if ! TRIPLE="$(triple_for "${ABI}")"; then
        echo "Unknown ABI in LIBFFI_ABIS: ${ABI}" >&2
        echo "Known: arm64-v8a armeabi-v7a x86_64 x86" >&2
        exit 1
    fi
    build_abi "${ABI}" "${TRIPLE}"
done

echo
echo "Done. Static libffi installed under:"
for ABI in ${ABIS}; do
    echo "  ${WORK_DIR}/install/${ABI}"
done
