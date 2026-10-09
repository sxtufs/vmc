#include "vmp_file.h"

#include <android/log.h>
#include <string.h>

#include "vmp_log.h"

/*
 * Reads the little-endian VMP2 blob emitted by VmcWriter. The 112-byte header
 * describes strings, descriptor tables, string IDs, code, and data; optional
 * IR and permutation sections are described by slots 96/100 and 92. Version 1
 * uses dense string IDs, version 2 uses sparse string IDs, and feature bit 0
 * selects sparse descriptor tables.
 */

#include "vmp_abi.h"
#include "vmp_ir.h"
#include "vmp_sigblock.h"

#define VMP_PERM_LUT_COUNT 8
#define VMP_PERM_LUT_AREA (VMP_PERM_LUT_COUNT * 256)

static const uint32_t VMP2_HEADER_SIZE = 112;

static const uint32_t SEC_STRINGS = 28;
static const uint32_t SEC_TYPES = 36;
static const uint32_t SEC_PROTOS = 44;
static const uint32_t SEC_FIELDS = 52;
static const uint32_t SEC_METHODS = 60;
static const uint32_t SEC_CODE = 68;
static const uint32_t SEC_DATA = 76;

static const uint32_t FEATURE_SPARSE_DESCRIPTORS = 1;

static inline uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint16_t rd_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

/**
 * DEX type descriptor -> the internal form FindClass expects; false when [desc]
 * is not one. The shape test prevents the `strlen(desc) - 2` underflow: a 0/1-char
 * descriptor (what a pruned table entry yields) would throw inside a JNI callback
 * - std::terminate under -fno-exceptions. Array descriptors pass through.
 */
static bool descriptorToJni(const char *desc, std::string *out) {
    if (!desc || !out) return false;
    const size_t dl = strlen(desc);
    if (dl == 0) return false;
    if (desc[0] == '[') { out->assign(desc, dl); return true; }
    if (dl < 3 || desc[0] != 'L' || desc[dl - 1] != ';') return false;
    out->assign(desc + 1, dl - 2);
    return true;
}

static void clearPending(JNIEnv *env) {
    if (env->ExceptionCheck()) env->ExceptionClear();
}


VmpFile::VmpFile() = default;
VmpFile::~VmpFile() {
    data_ = nullptr;
    size_ = 0;
}

bool VmpFile::open(const uint8_t *data, size_t size) {
    if (!data || size < VMP2_HEADER_SIZE) {
        LOGE("VMP2: buffer too small (%zu)", size);
        return false;
    }
    if (rd_u32(data) != 0x32504d56) {
        LOGE("VMP2: bad magic");
        return false;
    }
    if (rd_u32(data) != 0x32504d56) {
        LOGE("VMP2: bad magic");
        return false;
    }
    if ((uint64_t)rd_u32(data + 8) != (uint64_t)size ||
        rd_u32(data + 12) != VMP2_HEADER_SIZE ||
        rd_u32(data + 16) != 0x12345678u) {
        LOGE("VMP2: inconsistent header size=%u header=%u endian=%08x",
             rd_u32(data + 8), rd_u32(data + 12), rd_u32(data + 16));
        return false;
    }
    version_ = rd_u32(data + 4);
    if (version_ < 1 || version_ > VMP_ABI_MAX_CONTAINER_VERSION) {
        LOGE("VMP2: container version %u needs runtime %s",
             version_, VMP_ABI_TOKEN);
        return false;
    }
    data_ = data;
    size_ = size;

    strings_off_ = rd_u32(data + SEC_STRINGS + 4);
    strings_size_ = rd_u32(data + SEC_STRINGS);
    types_off_ = rd_u32(data + SEC_TYPES + 4);
    types_size_ = rd_u32(data + SEC_TYPES);
    protos_off_ = rd_u32(data + SEC_PROTOS + 4);
    protos_size_ = rd_u32(data + SEC_PROTOS);
    fields_off_ = rd_u32(data + SEC_FIELDS + 4);
    fields_size_ = rd_u32(data + SEC_FIELDS);
    methods_off_ = rd_u32(data + SEC_METHODS + 4);
    methods_size_ = rd_u32(data + SEC_METHODS);
    code_off_ = rd_u32(data + SEC_CODE + 4);
    code_size_ = rd_u32(data + SEC_CODE);
    data_section_off_ = rd_u32(data + SEC_DATA + 4);
    data_section_size_ = rd_u32(data + SEC_DATA);

    struct SecChk { uint32_t off, sz; const char *name; };
    const SecChk secs[] = {
        { strings_off_, strings_size_, "strings" },
        { types_off_,    types_size_,    "types" },
        { protos_off_,   protos_size_,   "protos" },
        { fields_off_,   fields_size_,   "fields" },
        { methods_off_,  methods_size_,  "methods" },
        { code_off_,     code_size_,     "code" },
        { data_section_off_, data_section_size_, "data" },
    };
    for (const SecChk &s : secs) {
        if (s.sz != 0 &&
            (s.off < VMP2_HEADER_SIZE ||
             (uint64_t)s.off + (uint64_t)s.sz > (uint64_t)size)) {
            LOGE("VMP2: %s section out of range (off=%u size=%u buffer=%zu)",
                 s.name, s.off, s.sz, size);
            return false;
        }
    }
    for (size_t i = 0; i < sizeof(secs) / sizeof(secs[0]); i++) {
        if (secs[i].sz == 0) continue;
        for (size_t j = i + 1; j < sizeof(secs) / sizeof(secs[0]); j++) {
            if (secs[j].sz == 0) continue;
            const uint64_t a0 = secs[i].off;
            const uint64_t a1 = a0 + secs[i].sz;
            const uint64_t b0 = secs[j].off;
            const uint64_t b1 = b0 + secs[j].sz;
            if (a0 < b1 && b0 < a1) {
                LOGE("VMP2: sections %s and %s overlap", secs[i].name, secs[j].name);
                return false;
            }
        }
    }
    if (code_size_ % 36 != 0) {
        LOGE("VMP2: bad code table size %u", code_size_);
        return false;
    }

    features_ = rd_u32(data + 20);
    sparseDesc_ = (features_ & FEATURE_SPARSE_DESCRIPTORS) != 0;
    if (sparseDesc_) {
        struct DescChk { uint32_t off, sz, stride; const char *name; };
        const DescChk ds[] = {
            { types_off_,   types_size_,   4,  "types"   },
            { fields_off_,  fields_size_,  8,  "fields"  },
            { methods_off_, methods_size_, 8,  "methods" },
            { protos_off_,  protos_size_,  12, "protos"  },
        };
        for (const DescChk &d : ds) {
            const uint8_t *b = data_ + d.off;
            if (d.sz < 4) {
                LOGE("VMP2: %s section too small for the sparse form (%u)",
                     d.name, d.sz);
                return false;
            }
            const uint32_t n32 = rd_u32(b);
            const uint64_t indexSize = 4ull + 8ull * (uint64_t)n32;
            if (indexSize > (uint64_t)d.sz) {
                LOGE("VMP2: %s sparse index claims %u entries in %u bytes",
                     d.name, n32, d.sz);
                return false;
            }
            uint32_t prev = 0;
            for (uint32_t k = 0; k < n32; k++) {
                const uint8_t *e = b + 4 + 8ull * k;
                const uint32_t id = rd_u32(e);
                const uint32_t rec = rd_u32(e + 4);
                if ((k > 0 && id <= prev) ||
                    (uint64_t)rec < indexSize ||
                    (uint64_t)rec + d.stride > (uint64_t)d.sz) {
                    LOGE("VMP2: %s sparse table malformed at entry %u",
                         d.name, k);
                    return false;
                }
                prev = id;
            }
        }
    }

    strids_size_ = rd_u32(data + 84);
    strids_off_ = rd_u32(data + 88);
    if (strids_size_ != 0 &&
        (strids_off_ < VMP2_HEADER_SIZE ||
         (uint64_t)strids_off_ + (uint64_t)strids_size_ > (uint64_t)size)) {
        LOGE("VMP2: string-id table out of range (off=%u size=%u)",
             strids_off_, strids_size_);
        return false;
    }
    if (strids_size_ != 0) {
        const uint64_t s0 = strids_off_;
        const uint64_t s1 = s0 + strids_size_;
        for (const SecChk &s : secs) {
            if (s.sz == 0) continue;
            const uint64_t a0 = s.off;
            const uint64_t a1 = a0 + s.sz;
            if (a0 < s1 && s0 < a1) {
                LOGE("VMP2: string-id table overlaps %s", s.name);
                return false;
            }
        }
    }
    if (strids_size_ == 0 && code_size_ != 0) {
        LOGE("VMP2: missing string-id table");
        return false;
    }

    methods_count_ = (int)(code_size_ / 36);
    static_assert(sizeof(VmMethod) == 36, "code record is 9 x u32");
    code_table_.resize((size_t)methods_count_);
    for (int i = 0; i < methods_count_; i++)
        memcpy(&code_table_[(size_t)i], data_ + code_off_ + (size_t)i * 36u,
               sizeof(VmMethod));

    for (int i = 0; i < methods_count_; i++) {
        const VmMethod &r = code_table_[i];
        if (r.regs < 0 || r.regs > 0xFFFF ||
                r.ins < 0 || r.ins > 0xFFFF ||
                r.outs < 0 || r.outs > 0xFFFF) {
            LOGE("VMP2: method %d impossible frame (regs=%d ins=%d outs=%d)",
                 i, r.regs, r.ins, r.outs);
            return false;
        }
        if (r.ins > r.regs) {
            LOGE("VMP2: method %d ins=%d exceeds regs=%d", i, r.ins, r.regs);
            return false;
        }
        if (r.insns_size < 0) {
            LOGE("VMP2: method %d negative insns_size=%d", i, r.insns_size);
            return false;
        }
        if ((uint64_t)r.insns_off + (uint64_t)r.insns_size * 2u >
                (uint64_t)data_section_size_) {
            LOGE("VMP2: method %d insns off=%u size=%d exceeds data section "
                 "(sec off=%u size=%u buffer=%zu)",
                 i, r.insns_off, r.insns_size,
                 data_section_off_, data_section_size_, size);
            return false;
        }
        if (r.tries_size < 0 ||
            (r.tries_size > 0 &&
             (uint64_t)r.tries_off + (uint64_t)r.tries_size * 16u >
                 (uint64_t)data_section_size_)) {
            LOGE("VMP2: method %d tries off=%u count=%d outside the data section",
                 i, r.tries_off, r.tries_size);
            return false;
        }
    }

    insn_state_.reset(methods_count_ > 0
            ? new std::atomic<uint8_t>[(size_t)methods_count_]()
            : nullptr);
    insn_state_n_ = (methods_count_ > 0) ? (size_t)methods_count_ : 0;

    irCnt_.assign((size_t)(code_size_ / 36), 0u);
    irW_.assign(irCnt_.size(), nullptr);
    irSha_.assign(irCnt_.size(), nullptr);
    if (version_ >= 6) {
        const uint32_t irOff = rd_u32(data + VMP_IR_OFF_SLOT);
        const uint32_t irSize = rd_u32(data + VMP_IR_SIZE_SLOT);
        const size_t nrec = irCnt_.size();
        bool bad = irOff < 112 || irSize < 4 ||
                   (uint64_t)irOff + irSize > (uint64_t)size;
        if (!bad && rd_u32(data + irOff) != (uint32_t)nrec) bad = true;
        for (size_t r = 0; r < nrec && !bad; r++) {
            const uint32_t tab = rd_u32(data + irOff + 4 + 4u * r);
            if (tab == 0) continue;
            if ((uint64_t)tab + 2 + 32 > irSize) { bad = true; break; }
            const uint8_t *t = data + irOff + tab;
            const uint32_t n = rd_u16(t);
            if (n == 0 ||
                    (uint64_t)tab + 2 + 2u * n + 32 > irSize) { bad = true; break; }
            uint64_t sum = 0;
            bool wbad = false;
            for (uint32_t j = 0; j < n; j++) {
                const uint32_t wj = rd_u16(t + 2 + 2u * j);
                if (wj < 1 || wj > 8) { wbad = true; break; }
                sum += wj;
            }
            const VmMethod &m = code_table_[r];
            if (wbad || sum != (uint64_t)(uint32_t)m.insns_size ||
                    (uint64_t)m.insns_off + (uint64_t)n * 16u >
                        (uint64_t)data_section_size_) { bad = true; break; }
            irCnt_[r] = n;
            irW_[r] = (const uint16_t *)(t + 2);
            irSha_[r] = t + 2 + 2u * n;
        }
        if (bad) {
            LOGE("VMP2: malformed IR section - container rejected");
            return false;
        }
    }

    permBase_ = nullptr;
    permMulti_ = false;
    permIdxBase_ = 256;
    if (version_ >= 4) {
        const bool multi = version_ >= 5;
        const uint32_t permOff = rd_u32(data + 92);
        const size_t nrec = (size_t)(code_size_ / 36);
        const uint64_t idxBase =
            (uint64_t)(multi ? VMP_PERM_LUT_AREA : 256) + (multi ? (uint64_t)nrec : 0u);
        bool bad = permOff < 112 ||
                   (uint64_t)permOff + idxBase + 4 * nrec > (uint64_t)size;
        if (!bad) {
            const int nlut = multi ? VMP_PERM_LUT_COUNT : 1;
            for (int l = 0; l < nlut && !bad; l++) {
                const uint8_t *lut = data + permOff + (uint64_t)l * 256;
                bool seen[256] = {false};
                for (int i = 0; i < 256; i++) {
                    if (seen[lut[i]]) { bad = true; break; }
                    seen[lut[i]] = true;
                }
            }
        }
        if (!bad && multi) {
            const uint8_t *sel = data + permOff + VMP_PERM_LUT_AREA;
            for (size_t r = 0; r < nrec; r++)
                if (sel[r] >= VMP_PERM_LUT_COUNT) { bad = true; break; }
        }
        if (!bad) {
            const uint8_t *idx = data + permOff + idxBase;
            for (size_t r = 0; r < nrec && !bad; r++) {
                const uint32_t rel = rd_u32(idx + 4 * r);
                if (rel < (uint32_t)idxBase ||
                    (uint64_t)rel + 2 > (uint64_t)(size - permOff)) { bad = true; break; }
                const uint8_t *t = data + permOff + rel;
                const uint32_t cnt = rd_u16(t);
                if (cnt < 1 || (uint64_t)rel + 2 + 2u * cnt > (uint64_t)(size - permOff)) { bad = true; break; }
                const uint32_t isz = code_table_[r].insns_size;
                int prev = -1;
                for (uint32_t j = 0; j < cnt && !bad; j++) {
                    const int s = rd_u16(t + 2 + 2 * j);
                    if ((j == 0 && s != 0) || (j > 0 && s <= prev) ||
                        (uint32_t)s >= isz) bad = true;
                    prev = s;
                }
            }
        }
        if (bad) {
            LOGE("VMP2: malformed perm section - container rejected");
            return false;
        }
        permBase_ = data + permOff;
        permMulti_ = multi;
        permIdxBase_ = (uint32_t)idxBase;
    }

    code_idx_by_method_id_.clear();
    code_idx_by_method_id_.reserve((size_t)methods_count_ * 2 + 1);
    for (int i = 0; i < methods_count_; i++) {
        code_idx_by_method_id_[code_table_[i].method_id_idx] = i;
    }

    if (version_ >= 3 && methods_count_ > 0)
        vmpNoteLazyFile();

    LOGI("VMP2 opened: methods=%d strings=%u data_off=%u data_size=%u",
         methods_count_, strings_size_, data_section_off_, data_section_size_);
    return true;
}

bool VmpFile::stringInBounds(uint32_t off) const {
    if (!data_ || strings_size_ == 0) return false;
    if ((uint64_t)off >= (uint64_t)strings_size_) return false;
    const uint8_t *s = data_ + strings_off_ + (size_t)off;
    const uint8_t *secEnd = data_ + strings_off_ + (size_t)strings_size_;
    return memchr(s, 0, (size_t)(secEnd - s)) != nullptr;
}

const char *VmpFile::getString(uint32_t offset) const {
    if (!stringInBounds(offset)) return nullptr;
    return (const char *)(data_ + strings_off_ + (size_t)offset);
}

const uint8_t *VmpFile::descRec(uint32_t secOff, uint32_t secSize,
                                uint32_t stride, uint32_t id) const {
    if (!data_ || secSize == 0) return nullptr;
    const uint8_t *base = data_ + secOff;

    if (!sparseDesc_) {
        if ((uint64_t)id * stride + stride > (uint64_t)secSize) return nullptr;
        return base + (uint64_t)id * stride;
    }

    if (secSize < 4) return nullptr;
    const uint32_t n = rd_u32(base);
    if (4ull + 8ull * (uint64_t)n > (uint64_t)secSize) return nullptr;
    const uint8_t *idx = base + 4;
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        const uint8_t *e = idx + 8ull * mid;
        const uint32_t key = rd_u32(e);
        if (key == id) {
            const uint32_t recOff = rd_u32(e + 4);
            if ((uint64_t)recOff + stride > (uint64_t)secSize) return nullptr;
            return base + recOff;
        }
        if (key < id) lo = mid + 1; else hi = mid;
    }
    return nullptr;
}

const uint8_t *VmpFile::methodRec(int methodIdx) const {
    if (methodIdx < 0) return nullptr;
    return descRec(methods_off_, methods_size_, 8, (uint32_t)methodIdx);
}

/**
 * Resolves a DEX string_id INDEX through the string-id table (slots 84/88). nullptr
 * when the table is missing or the index is out of range (a hard error downstream).
 */
const char *VmpFile::getStringById(uint32_t stringId) const {
    if (!data_ || strids_size_ == 0) return nullptr;

    if (version_ >= 2) {
        if (strids_size_ < 4) return nullptr;
        const uint32_t n = rd_u32(data_ + strids_off_);
        if ((uint64_t)n * 8 + 4 > (uint64_t)strids_size_) return nullptr;
        const uint8_t *base = data_ + strids_off_ + 4;
        uint32_t lo = 0, hi = n;
        while (lo < hi) {
            const uint32_t mid = lo + (hi - lo) / 2;
            const uint32_t key = rd_u32(base + (size_t)mid * 8);
            if (key == stringId) {
                const uint32_t off = rd_u32(base + (size_t)mid * 8 + 4);
                if (!stringInBounds(off)) return nullptr;
                return (const char *)(data_ + strings_off_ + (size_t)off);
            }
            if (key < stringId) lo = mid + 1; else hi = mid;
        }
        return nullptr;
    }

    if ((uint64_t)stringId * 4 + 4 > (uint64_t)strids_size_) return nullptr;
    uint32_t off = rd_u32(data_ + strids_off_ + (size_t)stringId * 4);
    if (!stringInBounds(off)) return nullptr;
    return (const char *)(data_ + strings_off_ + (size_t)off);
}

const char *VmpFile::getTypeDescriptor(uint32_t typeIdx) const {
    const uint8_t *r = descRec(types_off_, types_size_, 4, typeIdx);
    if (!r) return nullptr;
    return getString(rd_u32(r));
}

static const uint32_t *protoChecked(const uint8_t *base, const uint8_t *p,
                                    const uint8_t *end) {
    if (!p || p > end || (size_t)(end - p) < 4) return nullptr;
    const uint32_t paramCount = rd_u32(p);
    if ((uint64_t)(p - base) + 4 + (uint64_t)paramCount * 4 + 8 >
        (uint64_t)(end - base)) {
        return nullptr;
    }
    return (const uint32_t *)p;
}

const uint32_t *VmpFile::getProtoPtr(uint32_t protoIdx) const {
    if (!data_ ||
        (uint64_t)protos_off_ + (uint64_t)protos_size_ > (uint64_t)size_)
        return nullptr;
    const uint8_t *base = data_ + protos_off_;
    const uint8_t *end = base + protos_size_;

    if (sparseDesc_)
        return protoChecked(base, descRec(protos_off_, protos_size_, 12, protoIdx), end);

    const uint8_t *p = base;
    uint32_t n = 0;
    while (p < end && n < protoIdx) {
        if (p + 4 > end) return nullptr;
        const uint32_t paramCount = rd_u32(p);
        if ((uint64_t)(p - base) + 4 + (uint64_t)paramCount * 4 + 8 >
            (uint64_t)(end - base)) {
            return nullptr;
        }
        p += 4 + paramCount * 4 + 8;
        n++;
    }
    return protoChecked(base, p, end);
}

static inline uint32_t proto_slot(const uint32_t *p, uint32_t i) {
    return rd_u32((const uint8_t *)p + (size_t)i * 4u);
}

const char *VmpFile::getProtoShorty(uint32_t protoIdx) const {
    const uint32_t *p = getProtoPtr(protoIdx);
    if (!p) return nullptr;
    const uint32_t paramCount = proto_slot(p, 0);
    return getString(proto_slot(p, 1 + paramCount));
}

const char *VmpFile::getProtoSig(uint32_t protoIdx) const {
    const uint32_t *p = getProtoPtr(protoIdx);
    if (!p) return nullptr;
    const uint32_t paramCount = proto_slot(p, 0);
    return getString(proto_slot(p, 2 + paramCount));
}

const VmMethod *VmpFile::getMethod(int idx) const {
    if (idx < 0 || idx >= methods_count_) return nullptr;
    return &code_table_[idx];
}

const char *VmpFile::getMethodClass(int methodIdx) const {
    const uint8_t *p = methodRec(methodIdx);
    if (!p) return nullptr;
    return getTypeDescriptor(rd_u16(p));
}

const char *VmpFile::getMethodName(int methodIdx) const {
    const uint8_t *p = methodRec(methodIdx);
    if (!p) return nullptr;
    return getString(rd_u32(p + 4));
}

const char *VmpFile::getMethodShorty(int methodIdx) const {
    const uint8_t *p = methodRec(methodIdx);
    if (!p) return nullptr;
    return getProtoShorty(rd_u16(p + 2));
}

const char *VmpFile::getMethodSig(int methodIdx) const {
    const uint8_t *p = methodRec(methodIdx);
    if (!p) return nullptr;
    return getProtoSig(rd_u16(p + 2));
}

void VmpFile::getFieldId(uint32_t fieldIdx, uint32_t *cls, uint32_t *type, uint32_t *name) const {
    if (cls) *cls = 0;
    if (type) *type = 0;
    if (name) *name = 0;
    const uint8_t *p = descRec(fields_off_, fields_size_, 8, fieldIdx);
    if (!p) return;
    if (cls) *cls = rd_u16(p);
    if (type) *type = rd_u16(p + 2);
    if (name) *name = rd_u32(p + 4);
}

const uint16_t *VmpFile::getInsns(const VmMethod *m) const {
    if (!m) return nullptr;
    uint8_t *base = const_cast<uint8_t *>(data_) + data_section_off_;
    const int idx = (int)(m - code_table_.data());
    const bool tracked = idx >= 0 && (size_t)idx < insn_state_n_;
    if (version_ >= 3 && tracked) {
        if (!all_insns_ready_.load(std::memory_order_relaxed) &&
            insn_state_[idx].load(std::memory_order_acquire) < 2) {
            std::lock_guard<std::mutex> lk(insnMutex_);
            if (insn_state_[idx].load(std::memory_order_relaxed) < 2) {
                const uint32_t irn =
                    (size_t)idx < irCnt_.size() ? irCnt_[(size_t)idx] : 0u;
                vmp_decryptInsns(base + m->insns_off,
                                 irn ? (size_t)irn * 16u
                                     : (size_t)m->insns_size * 2u,
                                 m->insns_off);
                if (irn) {
                    vmpIrExpand(base + m->insns_off, irW_[(size_t)idx], irn);
                }
                if (version_ >= 4 && permBase_) {
                    const uint8_t *lut = permBase_;
                    if (permMulti_)
                        lut = permBase_ +
                              (uint32_t)permBase_[VMP_PERM_LUT_AREA +
                                                  (uint32_t)idx] * 256u;
                    const uint8_t *t =
                        permBase_ + rd_u32(permBase_ + permIdxBase_ +
                                           4u * (unsigned)idx);
                    const uint32_t cnt = rd_u16(t);
                    uint8_t *ip = base + m->insns_off;
                    for (uint32_t j = 0; j < cnt; j++) {
                        uint8_t *q = ip + (size_t)rd_u16(t + 2 + 2u * j) * 2u;
                        *q = lut[*q];
                    }
                }
                bool refused = false;
                if (irn) {
                    uint8_t *reg = base + m->insns_off;
                    uint8_t d[32];
                    if (!vmpSha256(reg, vmpIrPlainLen(irW_[(size_t)idx], irn), d) ||
                        memcmp(d, irSha_[(size_t)idx], 32) != 0) {
                        LOGDIAG("vmp-file: IR digest refusal (record %d)", idx);
                        refused = true;
                    }
                }
                insn_state_[idx].store(refused ? 3 : 2, std::memory_order_release);
                bool all_done = true;
                for (size_t i = 0; i < insn_state_n_; i++) {
                    if (insn_state_[i].load(std::memory_order_relaxed) < 2) {
                        all_done = false; break;
                    }
                }
                if (all_done) {
                    all_insns_ready_.store(true, std::memory_order_release);
                    vmpLazyFileReady();
                }
                if (refused) return nullptr;
            }
        }
        if (insn_state_[idx].load(std::memory_order_acquire) >= 3) return nullptr;
    }
    return (const uint16_t *)(base + m->insns_off);
}

const uint32_t *VmpFile::getTries(const VmMethod *m) const {
    if (!m || m->tries_size <= 0) return nullptr;
    return (const uint32_t *)(data_ + data_section_off_ + m->tries_off);
}

jclass VmpFile::classOf(JNIEnv *env, int methodIdx) {
    std::lock_guard<std::recursive_mutex> lk(cacheMutex_);
    auto it = cached_classes_.find(methodIdx);
    if (it != cached_classes_.end()) return it->second;

    std::string jniName;
    if (!descriptorToJni(getMethodClass(methodIdx), &jniName)) {
        LOGE("classOf: not a class descriptor (method %d)", methodIdx);
        return nullptr;
    }
    jclass local = env->FindClass(jniName.c_str());
    if (!local) {
        clearPending(env);
        LOGE("FindClass failed for %s", jniName.c_str());
        return nullptr;
    }
    jclass global = (jclass)env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    cached_classes_[methodIdx] = global;
    return global;
}

jclass VmpFile::classOfType(JNIEnv *env, uint32_t typeIdx) {
    std::lock_guard<std::recursive_mutex> lk(cacheMutex_);
    auto it = cached_types_.find((int)typeIdx);
    if (it != cached_types_.end()) return it->second;
    std::string jniName;
    if (!descriptorToJni(getTypeDescriptor(typeIdx), &jniName)) return nullptr;
    jclass local = env->FindClass(jniName.c_str());
    if (!local) { clearPending(env); return nullptr; }
    jclass global = (jclass)env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    cached_types_[(int)typeIdx] = global;
    return global;
}

jmethodID VmpFile::methodOf(JNIEnv *env, int methodIdx, bool isStatic) {
    std::lock_guard<std::recursive_mutex> lk(cacheMutex_);
    auto key = methodIdx * 2 + (isStatic ? 1 : 0);
    auto it = cached_methods_.find(key);
    if (it != cached_methods_.end()) return it->second;

    jclass clazz = classOf(env, methodIdx);
    if (!clazz) return nullptr;

    const char *name = getMethodName(methodIdx);
    const char *sig = getMethodSig(methodIdx);
    if (!name || !sig) return nullptr;

    jmethodID mid = isStatic
        ? env->GetStaticMethodID(clazz, name, sig)
        : env->GetMethodID(clazz, name, sig);
    if (!mid) {
        clearPending(env);
        LOGE("Get%sMethodID failed for %s.%s",
             isStatic ? "Static" : "", name, sig);
        return nullptr;
    }
    cached_methods_[key] = mid;
    return mid;
}

jfieldID VmpFile::fieldOf(JNIEnv *env, int fieldIdx, bool isStatic) {
    std::lock_guard<std::recursive_mutex> lk(cacheMutex_);
    auto key = fieldIdx * 2 + (isStatic ? 1 : 0);
    auto it = cached_fields_.find(key);
    if (it != cached_fields_.end()) return it->second;

    const uint8_t *p = descRec(fields_off_, fields_size_, 8, (uint32_t)fieldIdx);
    if (!p) return nullptr;
    uint16_t classIdx = rd_u16(p);
    uint16_t typeIdx = rd_u16(p + 2);
    uint32_t nameOff = rd_u32(p + 4);

    const char *classDesc = getTypeDescriptor(classIdx);
    const char *fieldType = getTypeDescriptor(typeIdx);
    const char *fieldName = stringInBounds(nameOff)
        ? (const char *)(data_ + strings_off_ + (size_t)nameOff) : nullptr;
    if (!fieldType || !fieldName) return nullptr;

    std::string jniName;
    if (!descriptorToJni(classDesc, &jniName)) return nullptr;
    jclass clazz = env->FindClass(jniName.c_str());
    if (!clazz) { clearPending(env); return nullptr; }

    jfieldID fid = isStatic
        ? env->GetStaticFieldID(clazz, fieldName, fieldType)
        : env->GetFieldID(clazz, fieldName, fieldType);
    env->DeleteLocalRef(clazz);
    if (!fid) {
        clearPending(env);
        LOGE("Get%sFieldID failed for %s.%s", isStatic ? "Static" : "", fieldName, fieldType);
        return nullptr;
    }
    cached_fields_[key] = fid;
    return fid;
}

int VmpFile::codeIndexOfMethodId(int methodIdIdx) const {
    auto it = code_idx_by_method_id_.find(methodIdIdx);
    return it != code_idx_by_method_id_.end() ? it->second : -1;
}

const VmMethod *VmpFile::getMethodByMethodId(int methodIdIdx) const {
    int idx = codeIndexOfMethodId(methodIdIdx);
    return idx >= 0 ? getMethod(idx) : nullptr;
}