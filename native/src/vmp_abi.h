#ifndef VMP_ABI_H
#define VMP_ABI_H

/**
 * Runtime capability contract. The packer reads VMP_ABI_TOKEN from the source
 * and built library. VMP_ABI_MAX_CONTAINER_VERSION is the highest VMP2
 * container version accepted by this runtime; it is independent of the token.
 */
#define VMP_ABI_TOKEN "vmp.abi.10"

/** Highest VMP2 container version this runtime can parse. */
#define VMP_ABI_MAX_CONTAINER_VERSION 6u

#endif // VMP_ABI_H
