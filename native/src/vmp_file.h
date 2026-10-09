#ifndef VMP_FILE_H
#define VMP_FILE_H

#include <jni.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <memory>
#include <android/asset_manager.h>

/**
 * VMP2 is a little-endian in-memory blob. Its 112-byte header contains the
 * magic, version, file size, endian marker, feature bits, and (size, offset)
 * pairs for strings, descriptor tables, code, and data. Slots 84/88 describe
 * the DEX string-ID table; slot 92 points to permutation data; slots 96/100
 * describe optional IR data. Version 1 uses dense string IDs, version 2 uses
 * sparse string IDs, and feature bit 0 selects sparse descriptor tables.
 */

void vmp_decryptInsns(uint8_t *p, size_t len, uint32_t insns_off);

void vmpNoteLazyFile();
void vmpLazyFileReady();

/** One VMP2 code-table record. */
struct VmMethod {
    int method_id_idx;
    int access;
    int regs;
    int ins;
    int outs;
    int insns_size;
    uint32_t insns_off;
    int tries_size;
    uint32_t tries_off;
};

/** Validated VMP2 view used by the interpreter. */
class VmpFile {
public:
    VmpFile();
    ~VmpFile();

    /**
     * Open a VMP2 container from a memory buffer. The buffer must remain
     * valid for the lifetime of this VmpFile.
     */
    bool open(const uint8_t *data, size_t size);

    const char *getString(uint32_t idx) const;
    /**
     * Resolves a DEX string_id INDEX through the string-id -> offset table
     * written by VmcWriter (header slot 84/88). The string blob itself is
     * sorted alphabetically, so a string_id index can never be used directly
     * as a blob offset. Returns nullptr when the table is missing (older
     * VMP2 blobs; repack required) or the index is out of range.
     */
    const char *getStringById(uint32_t stringId) const;
    const char *getTypeDescriptor(uint32_t typeIdx) const;
    const char *getProtoShorty(uint32_t protoIdx) const;

    int getMethodCount() const { return methods_count_; }
    const VmMethod *getMethod(int idx) const;
    const char *getMethodClass(int methodIdx) const;
    const char *getMethodName(int methodIdx) const;
    const char *getMethodShorty(int methodIdx) const;
    const uint32_t *getProtoPtr(uint32_t protoIdx) const;
    const char *getMethodSig(int methodIdx) const;
    const char *getProtoSig(uint32_t protoIdx) const;
    void getFieldId(uint32_t fieldIdx, uint32_t *cls, uint32_t *type, uint32_t *name) const;

    jclass classOf(JNIEnv *env, int methodIdx);
    jclass classOfType(JNIEnv *env, uint32_t typeIdx);
    jmethodID methodOf(JNIEnv *env, int methodIdx, bool isStatic);
    jfieldID fieldOf(JNIEnv *env, int fieldIdx, bool isStatic);

    /**
     * Code-table index of the virtualized method with DEX method-id index
     * [methodIdIdx], or -1 when that method id is NOT virtualized (it runs
     * as normal Java/ART code - a kept constructor, framework method, or a
     * method excluded by VirtualizationPolicy). Built once in open() from
     * the code table's method_id_idx fields. Dispatch itself is ALWAYS by
     * name (GetMethodID), so this map is for diagnostics/tracing only and
     * can never change call semantics.
     */
    int codeIndexOfMethodId(int methodIdIdx) const;

    /** The VmMethod for a DEX method-id index, or nullptr when not virtualized. */
    const VmMethod *getMethodByMethodId(int methodIdIdx) const;

    const uint16_t *getInsns(const VmMethod *m) const;
    const uint32_t *getTries(const VmMethod *m) const;

private:
    const uint8_t *data_ = nullptr;
    size_t size_ = 0;

    /**
     * Container format version read from header offset 4 in open().
     * 1 = every index table is dense (one slot per dex index).
     * 2 = the string-id table is sparse: u32 count followed by count x
     *     (u32 string_id_idx, u32 blob_offset) pairs sorted by index.
     * Validated in open(); an unknown version is a hard failure.
     */
    uint32_t version_ = 1;

    /**
     * Feature bits from header slot 20 (0 = the pre-feature layout).
     * Deliberately NOT another value of version_: ApkBuilder.encryptMethodInsns
     * assigns that field after VmcWriter has written it, so a format feature
     * living there would be silently overwritten.
     *
     * bit0 = the type/proto/field/method tables are sparse:
     *        [u32 count][count x (u32 id, u32 recOff)][records], ids strictly
     *        ascending, recOff relative to the section start. Fully validated in
     *        open(), so descRec() binary-searches without rechecking.
     */
    uint32_t features_ = 0;
    bool sparseDesc_ = false;

    uint32_t strings_off_ = 0;
    uint32_t strings_size_ = 0;
    uint32_t strids_off_ = 0;
    uint32_t strids_size_ = 0;
    /** True when [off] is a NUL-terminated offset within the strings section. */
    bool stringInBounds(uint32_t off) const;

    /** Return the validated dense/sparse descriptor record for [id]. */
    const uint8_t *descRec(uint32_t secOff, uint32_t secSize,
                           uint32_t stride, uint32_t id) const;

    /** Method-table record, or nullptr for a negative/pruned index. */
    const uint8_t *methodRec(int methodIdx) const;

    uint32_t types_off_ = 0;
    uint32_t types_size_ = 0;
    uint32_t protos_off_ = 0;
    uint32_t protos_size_ = 0;
    uint32_t fields_off_ = 0;
    uint32_t fields_size_ = 0;
    uint32_t methods_off_ = 0;
    uint32_t methods_size_ = 0;
    uint32_t code_off_ = 0;
    uint32_t code_size_ = 0;
    uint32_t data_section_off_ = 0;
    uint32_t data_section_size_ = 0;

    int methods_count_ = 0;
    std::vector<VmMethod> code_table_;

    const uint8_t *permBase_ = nullptr;
    bool permMulti_ = false;
    uint32_t permIdxBase_ = 256;
    std::vector<uint32_t> irCnt_;
    std::vector<const uint16_t *> irW_;
    std::vector<const uint8_t *> irSha_;
    mutable std::unique_ptr<std::atomic<uint8_t>[]> insn_state_;
    mutable size_t insn_state_n_ = 0;
    mutable std::mutex insnMutex_;
    mutable std::atomic<bool> all_insns_ready_{false};

    mutable std::recursive_mutex cacheMutex_;
    std::unordered_map<int, jclass> cached_classes_;
    std::unordered_map<int, jclass> cached_types_;
    std::unordered_map<int, jmethodID> cached_methods_;
    std::unordered_map<int, jfieldID> cached_fields_;

    std::unordered_map<int, int> code_idx_by_method_id_;

    mutable std::vector<std::vector<uint32_t>> proto_params_;
    mutable bool proto_params_parsed_ = false;
};

#endif