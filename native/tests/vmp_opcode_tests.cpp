#include <jni.h>

#include <algorithm>
#include <cmath>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "interpreter.h"
#include "vmp_file.h"

/**
 * Host-test implementations for runtime hooks that are unrelated to opcode
 * execution. The actual interpreter and VmpFile implementation are linked.
 */
void vmp_decryptInsns(uint8_t *, size_t, uint32_t) {}
void vmpNoteLazyFile() {}
void vmpLazyFileReady() {}
bool vmpSha256(const uint8_t *, size_t, uint8_t out[32]) {
    memset(out, 0, 32);
    return true;
}
bool vmpHmacSha256(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t out[32]) {
    memset(out, 0, 32);
    return true;
}
bool vmpInterpEnter(void) { return true; }
void vmpInterpLeave(void) {}

namespace {

struct Bytes {
    std::vector<uint8_t> data;

    Bytes() : data(112, 0) {}

    void u8(uint8_t v) { data.push_back(v); }
    void u16(uint16_t v) {
        u8(static_cast<uint8_t>(v));
        u8(static_cast<uint8_t>(v >> 8));
    }
    void u32(uint32_t v) {
        u16(static_cast<uint16_t>(v));
        u16(static_cast<uint16_t>(v >> 16));
    }
    void patch32(size_t offset, uint32_t v) {
        data[offset] = static_cast<uint8_t>(v);
        data[offset + 1] = static_cast<uint8_t>(v >> 8);
        data[offset + 2] = static_cast<uint8_t>(v >> 16);
        data[offset + 3] = static_cast<uint8_t>(v >> 24);
    }
};

struct FieldSpec {
    uint16_t classType = 0;
    uint16_t fieldType = 0;
    std::string name;
};

struct MethodRef {
    std::string classDescriptor;
    std::string name;
    std::string shorty;
    std::string signature;
};

struct CodeSpec {
    uint32_t methodIdIdx = 0;
    std::vector<uint16_t> insns;
    uint32_t registers = 1;
    uint32_t incoming = 0;
};

struct TrySpec {
    uint32_t startAddr = 0;
    uint32_t insnCount = 0;
    std::string typeDescriptor;
    uint32_t handlerAddr = 0;
};

struct MethodSpec {
    std::string shorty;
    std::string signature;
    std::vector<uint16_t> insns;
    uint32_t registers = 1;
    uint32_t incoming = 0;
    std::vector<std::string> typeDescriptors{"LHostOpcodeTest;"};
    std::vector<FieldSpec> fields;
    std::vector<MethodRef> referencedMethods;
    std::vector<CodeSpec> nestedCode;
    std::vector<TrySpec> tries;
    std::vector<std::string> stringLiterals;
};

static uint32_t appendString(Bytes &b, uint32_t stringsBase,
                              const std::string &s) {
    const uint32_t offset = static_cast<uint32_t>(b.data.size()) - stringsBase;
    b.data.insert(b.data.end(), s.begin(), s.end());
    b.u8(0);
    return offset;
}

static void appendSection(Bytes &b, uint32_t slot, const std::vector<uint8_t> &section) {
    const uint32_t offset = static_cast<uint32_t>(b.data.size());
    b.data.insert(b.data.end(), section.begin(), section.end());
    b.patch32(slot, static_cast<uint32_t>(section.size()));
    b.patch32(slot + 4, offset);
}

static std::vector<uint8_t> wordsToBytes(const std::vector<uint16_t> &words) {
    std::vector<uint8_t> result;
    result.reserve(words.size() * 2);
    for (uint16_t word : words) {
        result.push_back(static_cast<uint8_t>(word));
        result.push_back(static_cast<uint8_t>(word >> 8));
    }
    return result;
}

static std::vector<uint8_t> makeVmc(const MethodSpec &spec) {
    Bytes b;
    b.data[0] = 'V';
    b.data[1] = 'M';
    b.data[2] = 'P';
    b.data[3] = '2';
    b.patch32(4, 1);              // dense VMP2, no encryption/permutation
    b.patch32(12, 112);
    b.patch32(16, 0x12345678u);

    /**
     * String section. The first byte is the empty-string sentinel. VMP
     * metadata stores string references relative to this section, not as
     * absolute offsets into the enclosing blob.
     */
    const uint32_t stringsBase = static_cast<uint32_t>(b.data.size());
    b.u8(0);
    std::vector<uint32_t> typeOffsets;
    typeOffsets.reserve(spec.typeDescriptors.size());
    for (const std::string &descriptor : spec.typeDescriptors)
        typeOffsets.push_back(appendString(b, stringsBase, descriptor));
    const uint32_t classOffset = typeOffsets.front();
    const uint32_t shortyOffset = appendString(b, stringsBase, spec.shorty);
    const uint32_t signatureOffset = appendString(b, stringsBase, spec.signature);
    const uint32_t nameOffset = appendString(b, stringsBase, "test");
    std::vector<uint32_t> targetShortyOffsets;
    std::vector<uint32_t> targetSignatureOffsets;
    std::vector<uint32_t> targetNameOffsets;
    for (const MethodRef &target : spec.referencedMethods) {
        targetShortyOffsets.push_back(appendString(b, stringsBase, target.shorty));
        targetSignatureOffsets.push_back(appendString(b, stringsBase, target.signature));
        targetNameOffsets.push_back(appendString(b, stringsBase, target.name));
    }
    std::vector<uint32_t> fieldNameOffsets;
    fieldNameOffsets.reserve(spec.fields.size());
    for (const FieldSpec &field : spec.fields)
        fieldNameOffsets.push_back(appendString(b, stringsBase, field.name));
    std::vector<uint32_t> stringLiteralOffsets;
    stringLiteralOffsets.reserve(spec.stringLiterals.size());
    for (const std::string &literal : spec.stringLiterals)
        stringLiteralOffsets.push_back(appendString(b, stringsBase, literal));
    const uint32_t stringsSize = static_cast<uint32_t>(b.data.size()) - stringsBase;
    b.patch32(28, stringsSize);
    b.patch32(32, stringsBase);

    /**
     * Dense type records. Type index 0 is the declaring class; array and
     * element descriptors used by new-array/const-class follow it.
     */
    std::vector<uint8_t> types(typeOffsets.size() * 4);
    for (size_t i = 0; i < typeOffsets.size(); i++)
        memcpy(types.data() + i * 4, &typeOffsets[i], 4);
    appendSection(b, 36, types);

    /**
     * Variable-size proto records: parameter count, dummy parameter type
     * offsets, shorty string offset, and JNI signature string offset.
     */
    std::vector<uint8_t> protos;
    auto protoU32 = [&protos](uint32_t v) {
        protos.push_back(static_cast<uint8_t>(v));
        protos.push_back(static_cast<uint8_t>(v >> 8));
        protos.push_back(static_cast<uint8_t>(v >> 16));
        protos.push_back(static_cast<uint8_t>(v >> 24));
    };
    auto appendProto = [&](const std::string &shorty, const std::string &signature,
                           uint32_t shortyOffsetValue,
                           uint32_t signatureOffsetValue) {
        const uint32_t parameterCount = static_cast<uint32_t>(shorty.size() - 1);
        protoU32(parameterCount);
        for (uint32_t i = 0; i < parameterCount; i++) protoU32(classOffset);
        protoU32(shortyOffsetValue);
        protoU32(signatureOffsetValue);
    };
    appendProto(spec.shorty, spec.signature, shortyOffset, signatureOffset);
    for (size_t i = 0; i < spec.referencedMethods.size(); i++) {
        const MethodRef &target = spec.referencedMethods[i];
        appendProto(target.shorty, target.signature,
                    targetShortyOffsets[i], targetSignatureOffsets[i]);
    }
    appendSection(b, 44, protos);

    if (!spec.fields.empty()) {
        std::vector<uint8_t> fields(spec.fields.size() * 8, 0);
        for (size_t i = 0; i < spec.fields.size(); i++) {
            const FieldSpec &field = spec.fields[i];
            fields[i * 8] = static_cast<uint8_t>(field.classType);
            fields[i * 8 + 1] = static_cast<uint8_t>(field.classType >> 8);
            fields[i * 8 + 2] = static_cast<uint8_t>(field.fieldType);
            fields[i * 8 + 3] = static_cast<uint8_t>(field.fieldType >> 8);
            const uint32_t name = fieldNameOffsets[i];
            memcpy(fields.data() + i * 8 + 4, &name, 4);
        }
        appendSection(b, 52, fields);
    }

    /** Method records: caller is method id 0; referenced methods follow it. */
    std::vector<uint8_t> methods((1 + spec.referencedMethods.size()) * 8, 0);
    auto typeIndex = [&spec](const std::string &descriptor) -> uint16_t {
        for (size_t i = 0; i < spec.typeDescriptors.size(); i++) {
            if (spec.typeDescriptors[i] == descriptor)
                return static_cast<uint16_t>(i);
        }
        fprintf(stderr, "VMP test setup failed: missing type descriptor %s\n",
                descriptor.c_str());
        std::exit(2);
    };
    auto methodU16 = [&methods](size_t at, uint16_t value) {
        methods[at] = static_cast<uint8_t>(value);
        methods[at + 1] = static_cast<uint8_t>(value >> 8);
    };
    methodU16(0, 0);                   // caller class type index
    methodU16(2, 0);                   // caller proto index
    memcpy(methods.data() + 4, &nameOffset, 4);
    for (size_t i = 0; i < spec.referencedMethods.size(); i++) {
        const size_t at = (i + 1) * 8;
        methodU16(at, typeIndex(spec.referencedMethods[i].classDescriptor));
        methodU16(at + 2, static_cast<uint16_t>(i + 1));
        memcpy(methods.data() + at + 4, &targetNameOffsets[i], 4);
    }
    appendSection(b, 60, methods);

    /**
     * Code records are contiguous. Record zero is the caller; optional
     * records provide virtualized direct/static callees for nested-call tests.
     */
    std::vector<CodeSpec> codeSpecs;
    codeSpecs.push_back(CodeSpec{0, spec.insns, spec.registers, spec.incoming});
    codeSpecs.insert(codeSpecs.end(), spec.nestedCode.begin(), spec.nestedCode.end());
    std::vector<uint8_t> codeBytes;
    std::vector<uint32_t> insnOffsets;
    for (const CodeSpec &codeSpec : codeSpecs) {
        insnOffsets.push_back(static_cast<uint32_t>(codeBytes.size()));
        const std::vector<uint8_t> bytes = wordsToBytes(codeSpec.insns);
        codeBytes.insert(codeBytes.end(), bytes.begin(), bytes.end());
    }
    uint32_t triesOffset = 0;
    if (!spec.tries.empty()) {
        triesOffset = static_cast<uint32_t>(codeBytes.size());
        auto tryU32 = [&codeBytes](uint32_t value) {
            codeBytes.push_back(static_cast<uint8_t>(value));
            codeBytes.push_back(static_cast<uint8_t>(value >> 8));
            codeBytes.push_back(static_cast<uint8_t>(value >> 16));
            codeBytes.push_back(static_cast<uint8_t>(value >> 24));
        };
        for (const TrySpec &trySpec : spec.tries) {
            tryU32(trySpec.startAddr);
            tryU32(trySpec.insnCount);
            tryU32(trySpec.typeDescriptor.empty()
                   ? 0xffffffffu : typeIndex(trySpec.typeDescriptor));
            tryU32(trySpec.handlerAddr);
        }
    }
    std::vector<uint8_t> code(codeSpecs.size() * 36, 0);
    auto codeU32 = [&code](size_t at, uint32_t v) {
        code[at] = static_cast<uint8_t>(v);
        code[at + 1] = static_cast<uint8_t>(v >> 8);
        code[at + 2] = static_cast<uint8_t>(v >> 16);
        code[at + 3] = static_cast<uint8_t>(v >> 24);
    };
    for (size_t i = 0; i < codeSpecs.size(); i++) {
        const CodeSpec &codeSpec = codeSpecs[i];
        const size_t at = i * 36;
        codeU32(at + 0, codeSpec.methodIdIdx);
        codeU32(at + 4, 0x8);             // ACC_STATIC
        codeU32(at + 8, codeSpec.registers);
        codeU32(at + 12, codeSpec.incoming);
        codeU32(at + 16, 0);              // outs_size
        codeU32(at + 20, static_cast<uint32_t>(codeSpec.insns.size()));
        codeU32(at + 24, insnOffsets[i]); // insns_off within data
        codeU32(at + 28, i == 0 ? static_cast<uint32_t>(spec.tries.size()) : 0);
        codeU32(at + 32, i == 0 ? triesOffset : 0); // tries_off within data
    }
    appendSection(b, 68, code);
    appendSection(b, 76, codeBytes);

    /** Dense string-id table containing every string referenced by the fixture. */
    std::vector<uint8_t> strids;
    auto stridU32 = [&strids](uint32_t v) {
        strids.push_back(static_cast<uint8_t>(v));
        strids.push_back(static_cast<uint8_t>(v >> 8));
        strids.push_back(static_cast<uint8_t>(v >> 16));
        strids.push_back(static_cast<uint8_t>(v >> 24));
    };
    stridU32(0);
    for (uint32_t offset : typeOffsets) stridU32(offset);
    stridU32(shortyOffset);
    stridU32(signatureOffset);
    stridU32(nameOffset);
    for (size_t i = 0; i < spec.referencedMethods.size(); i++) {
        stridU32(targetShortyOffsets[i]);
        stridU32(targetSignatureOffsets[i]);
        stridU32(targetNameOffsets[i]);
    }
    for (uint32_t offset : fieldNameOffsets) stridU32(offset);
    appendSection(b, 84, strids);
    for (uint32_t offset : fieldNameOffsets) stridU32(offset);
    for (uint32_t offset : stringLiteralOffsets) stridU32(offset);
    appendSection(b, 84, strids);

    b.patch32(8, static_cast<uint32_t>(b.data.size()));
    return b.data;
}

static uint16_t op12(uint8_t op, int a, int b) {
    return static_cast<uint16_t>(op | (a << 8) | (b << 12));
}

static std::vector<uint16_t> op23(uint8_t op, int a, int b, int c, uint16_t ret) {
    return {
        static_cast<uint16_t>(op | (a << 8)),
        static_cast<uint16_t>(b | (c << 8)),
        ret
    };
}

static std::vector<uint16_t> op22b(uint8_t op, int a, int b, int8_t literal) {
    return {
        static_cast<uint16_t>(op | (a << 8)),
        static_cast<uint16_t>(b | ((static_cast<uint8_t>(literal)) << 8)),
        0x000f
    };
}

static std::vector<uint16_t> op22s(uint8_t op, int a, int b, int16_t literal) {
    return {
        static_cast<uint16_t>(op | (a << 8) | (b << 12)),
        static_cast<uint16_t>(literal),
        0x000f
    };
}

static std::vector<uint16_t> opWide23(uint8_t op, int a, int b, int c) {
    return {
        static_cast<uint16_t>(op | (a << 8)),
        static_cast<uint16_t>(b | (c << 8)),
        0x0010
    };
}

static std::vector<uint16_t> opWide12(uint8_t op, int a, int b) {
    return { op12(op, a, b), 0x0010 };
}
static void append12(std::vector<uint16_t> &code, uint8_t op, int a, int b) {
    code.push_back(op12(op, a, b));
}

static void append23(std::vector<uint16_t> &code, uint8_t op, int a, int b, int c) {
    code.push_back(static_cast<uint16_t>(op | (a << 8)));
    code.push_back(static_cast<uint16_t>(b | (c << 8)));
}

static void append21s(std::vector<uint16_t> &code, uint8_t op, int a, int16_t value) {
    code.push_back(static_cast<uint16_t>(op | (a << 8)));
    code.push_back(static_cast<uint16_t>(value));
}

static void appendNewArray(std::vector<uint16_t> &code, int dest, int sizeReg,
                           int typeIndex) {
    append12(code, 0x23, dest, sizeReg);
    code.push_back(static_cast<uint16_t>(typeIndex));
}

static void appendConstClass(std::vector<uint16_t> &code, int dest, int typeIndex) {
    code.push_back(static_cast<uint16_t>(0x1c | (dest << 8)));
    code.push_back(static_cast<uint16_t>(typeIndex));
}
static void append22c(std::vector<uint16_t> &code, uint8_t op,
                      int a, int b, int fieldIndex) {
    append12(code, op, a, b);
    code.push_back(static_cast<uint16_t>(fieldIndex));
}
static void append21c(std::vector<uint16_t> &code, uint8_t op,
                      int a, int fieldIndex) {
    code.push_back(static_cast<uint16_t>(op | (a << 8)));
    code.push_back(static_cast<uint16_t>(fieldIndex));
}


static void appendConstWide(std::vector<uint16_t> &code, int dest, int64_t value) {
    code.push_back(static_cast<uint16_t>(0x18 | (dest << 8)));
    const uint64_t bits = static_cast<uint64_t>(value);
    code.push_back(static_cast<uint16_t>(bits));
    code.push_back(static_cast<uint16_t>(bits >> 16));
    code.push_back(static_cast<uint16_t>(bits >> 32));
    code.push_back(static_cast<uint16_t>(bits >> 48));
}

static MethodRef invokeTarget(const char *classDescriptor, const char *name,
                              const char *shorty, const char *signature) {
    return MethodRef{classDescriptor, name, shorty, signature};
}

static void appendInvoke35c(std::vector<uint16_t> &code, uint8_t opcode,
                            int wordCount, int methodIndex,
                            const std::vector<int> &registers) {
    int raw[5] = {0, 0, 0, 0, 0};
    for (size_t i = 0; i < registers.size() && i < 5; i++) raw[i] = registers[i];
    code.push_back(static_cast<uint16_t>(opcode | (wordCount << 12) |
                                         (raw[4] << 8)));
    code.push_back(static_cast<uint16_t>(methodIndex));
    code.push_back(static_cast<uint16_t>(raw[0] | (raw[1] << 4) |
                                         (raw[2] << 8) | (raw[3] << 12)));
}

static void appendInvokeRange(std::vector<uint16_t> &code, uint8_t opcode,
                              int wordCount, int methodIndex, int firstRegister) {
    code.push_back(static_cast<uint16_t>(opcode | (wordCount << 8)));
    code.push_back(static_cast<uint16_t>(methodIndex));
    code.push_back(static_cast<uint16_t>(firstRegister));
}

static MethodSpec makeInvokeSpec(const std::string &shorty,
                                 const std::string &signature,
                                 const std::vector<uint16_t> &code,
                                 uint32_t registers, uint32_t incoming,
                                 const MethodRef &target,
                                 const std::vector<std::string> &types) {
    return MethodSpec{shorty, signature, code, registers, incoming, types, {}, {target}};
}

static MethodSpec makeInvokeVirtualInt(bool range = false) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x74, 1, 1, 1);
    else appendInvoke35c(code, 0x6e, 1, 1, {1});
    code.push_back(0x000a); // move-result v0
    code.push_back(0x000f);
    return makeInvokeSpec("IL", "(Ljava/lang/Integer;)I", code, 2, 1,
                          invokeTarget("Ljava/lang/Integer;", "intValue", "I", "()I"),
                          {"LHostOpcodeTest;", "Ljava/lang/Integer;"});
}

static MethodSpec makeInvokeDirectInt(bool range = false) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x76, 1, 1, 1);
    else appendInvoke35c(code, 0x70, 1, 1, {1});
    code.push_back(0x000a);
    code.push_back(0x000f);
    return makeInvokeSpec("IL", "(Ljava/lang/Integer;)I", code, 2, 1,
                          invokeTarget("Ljava/lang/Integer;", "intValue", "I", "()I"),
                          {"LHostOpcodeTest;", "Ljava/lang/Integer;"});
}

static MethodSpec makeInvokeSuperClass(bool range = false) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x75, 1, 1, 1);
    else appendInvoke35c(code, 0x6f, 1, 1, {1});
    code.push_back(0x000c); // move-result-object v0
    code.push_back(0x0011);
    return makeInvokeSpec("LL", "(Ljava/lang/Integer;)Ljava/lang/Class;", code, 2, 1,
                          invokeTarget("Ljava/lang/Object;", "getClass", "L", "()Ljava/lang/Class;"),
                          {"LHostOpcodeTest;", "Ljava/lang/Object;", "Ljava/lang/Integer;"});
}

static MethodSpec makeInvokeStaticInt(bool range = false, int resultReg = 0) {
    std::vector<uint16_t> code;
    const int registers = std::max(2, resultReg + 1);
    const int argBase = registers - 2;
    if (range) appendInvokeRange(code, 0x77, 2, 1, argBase);
    else appendInvoke35c(code, 0x71, 2, 1, {argBase, argBase + 1});
    code.push_back(op12(0x0a, resultReg, 0));
    code.push_back(op12(0x0f, resultReg, 0));
    return makeInvokeSpec("III", "(II)I", code, registers, 2,
                          invokeTarget("Ljava/lang/Math;", "max", "III", "(II)I"),
                          {"LHostOpcodeTest;", "Ljava/lang/Math;"});
}

static MethodSpec makeInvokeStaticVoid(bool range = false) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x77, 0, 1, 0);
    else appendInvoke35c(code, 0x71, 0, 1, {});
    append21s(code, 0x13, 0, 7);
    code.push_back(0x000f);
    return makeInvokeSpec("I", "()I", code, 1, 0,
                          invokeTarget("Ljava/lang/Thread;", "yield", "V", "()V"),
                          {"LHostOpcodeTest;", "Ljava/lang/Thread;"});
}

static MethodSpec makeInvokeVirtualWide() {
    std::vector<uint16_t> code;
    /**
     * With regs=3 and ins=1, the incoming receiver is initialized in v2.
     * v0/v1 remain available for move-result-wide.
     */
    appendInvoke35c(code, 0x6e, 1, 1, {2});
    code.push_back(0x000b); // move-result-wide v0
    code.push_back(0x0010);
    return makeInvokeSpec("JL", "(Ljava/lang/Long;)J", code, 3, 1,
                          invokeTarget("Ljava/lang/Long;", "longValue", "J", "()J"),
                          {"LHostOpcodeTest;", "Ljava/lang/Long;"});
}

static MethodSpec makeInvokeVirtualObject(int resultReg = 0) {
    std::vector<uint16_t> code;
    appendInvoke35c(code, 0x6e, 1, 1, {1});
    code.push_back(op12(0x0c, resultReg, 0));
    code.push_back(op12(0x11, resultReg, 0));
    return makeInvokeSpec("LL", "(Ljava/lang/Integer;)Ljava/lang/String;", code, 2, 1,
                          invokeTarget("Ljava/lang/Integer;", "toString", "L", "()Ljava/lang/String;"),
                          {"LHostOpcodeTest;", "Ljava/lang/Integer;"});
}

static MethodSpec makeInvokeVirtualArguments() {
    std::vector<uint16_t> code;
    appendInvoke35c(code, 0x6e, 3, 1, {1, 2, 3});
    code.push_back(0x000c);
    code.push_back(0x0011);
    return makeInvokeSpec("LLII", "(Ljava/lang/String;II)Ljava/lang/String;", code, 4, 3,
                          invokeTarget("Ljava/lang/String;", "substring", "LII",
                                       "(II)Ljava/lang/String;"),
                          {"LHostOpcodeTest;", "Ljava/lang/String;"});
}

static MethodSpec makeInvokeInterfaceInt(bool range = false) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x78, 1, 1, 1);
    else appendInvoke35c(code, 0x72, 1, 1, {1});
    code.push_back(0x000a);
    code.push_back(0x000f);
    return makeInvokeSpec("IL", "(Ljava/util/List;)I", code, 2, 1,
                          invokeTarget("Ljava/util/List;", "size", "I", "()I"),
                          {"LHostOpcodeTest;", "Ljava/util/List;"});
}

static MethodSpec makeInvokeInterfaceIndexOf(bool range = false) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x78, 2, 1, 1);
    else appendInvoke35c(code, 0x72, 2, 1, {1, 2});
    code.push_back(0x000a); // move-result v0
    code.push_back(0x000f); // return v0
    return makeInvokeSpec("ILL", "(Ljava/util/List;Ljava/lang/Object;)I",
                          code, 3, 2,
                          invokeTarget("Ljava/util/List;", "indexOf", "IL",
                                       "(Ljava/lang/Object;)I"),
                          {"LHostOpcodeTest;", "Ljava/lang/Object;",
                           "Ljava/util/List;"});
}

static MethodSpec makeInvokeStaticWide(bool range = false, int resultReg = 0) {
    std::vector<uint16_t> code;
    if (range) appendInvokeRange(code, 0x77, 4, 1, 2);
    else appendInvoke35c(code, 0x71, 4, 1, {2, 3, 4, 5});
    code.push_back(op12(0x0b, resultReg, 0));
    code.push_back(op12(0x10, resultReg, 0));
    return makeInvokeSpec("JJJ", "(JJ)J", code, 6, 4,
                          invokeTarget("Ljava/lang/Long;", "sum", "JJJ", "(JJ)J"),
                          {"LHostOpcodeTest;", "Ljava/lang/Long;"});
}

static MethodSpec makeNestedStaticInvoke() {
    std::vector<uint16_t> code;
    appendInvoke35c(code, 0x71, 2, 1, {0, 1});
    code.push_back(0x000a);
    code.push_back(0x000f);
    MethodSpec spec = makeInvokeSpec(
            "III", "(II)I", code, 2, 2,
            invokeTarget("Ljava/lang/Math;", "max", "III", "(II)I"),
            {"LHostOpcodeTest;", "Ljava/lang/Math;"});
    CodeSpec nested{1, {0x0013, 91, 0x000f}, 2, 2};
    spec.nestedCode.push_back(nested);
    return spec;
}

static MethodSpec makeInstanceIntField() {
    std::vector<uint16_t> code;
    append21s(code, 0x13, 0, 123);
    append22c(code, 0x59, 0, 1, 0); // iput v0, v1, i
    append22c(code, 0x52, 0, 1, 0); // iget v0, v1, i
    code.push_back(0x000f);
    return MethodSpec{"IL", "(LHostFields;)I", code, 2, 1,
                      {"LHostFields;", "I"}, {{0, 1, "i"}}};
}

static MethodSpec makeInstanceWideField() {
    std::vector<uint16_t> code;
    appendConstWide(code, 0, static_cast<int64_t>(0x1122334455667788ULL));
    append22c(code, 0x5a, 0, 2, 0); // iput-wide v0, v2, l
    append22c(code, 0x53, 0, 2, 0); // iget-wide v0, v2, l
    code.push_back(0x0010);
    return MethodSpec{"JL", "(LHostFields;)J", code, 3, 1,
                      {"LHostFields;", "J"}, {{0, 1, "l"}}};
}

static MethodSpec makeInstanceObjectField() {
    std::vector<uint16_t> code;
    append12(code, 0x07, 0, 2);       // move-object v0, v2
    append22c(code, 0x5b, 0, 1, 0);   // iput-object v0, v1, o
    append22c(code, 0x54, 0, 1, 0);   // iget-object v0, v1, o
    code.push_back(0x0011);
    return MethodSpec{"LLL", "(LHostFields;Ljava/lang/Object;)Ljava/lang/Object;",
                      code, 3, 2,
                      {"LHostFields;", "Ljava/lang/Object;"},
                      {{0, 1, "o"}}};
}

static MethodSpec makeStaticIntField() {
    std::vector<uint16_t> code;
    append21c(code, 0x67, 0, 0);      // sput v0, si
    append21c(code, 0x60, 0, 0);      // sget v0, si
    code.push_back(0x000f);
    return MethodSpec{"II", "(I)I", code, 1, 1,
                      {"LHostFields;", "I"}, {{0, 1, "si"}}};
}

static MethodSpec makeStaticWideField() {
    std::vector<uint16_t> code;
    append21c(code, 0x68, 0, 0);      // sput-wide v0, sl
    append21c(code, 0x61, 0, 0);      // sget-wide v0, sl
    code.push_back(0x0010);
    return MethodSpec{"JJ", "(J)J", code, 2, 2,
                      {"LHostFields;", "J"}, {{0, 1, "sl"}}};
}

static MethodSpec makeStaticObjectField() {
    std::vector<uint16_t> code;
    append21c(code, 0x69, 0, 0);      // sput-object v0, so
    append21c(code, 0x62, 0, 0);      // sget-object v0, so
    code.push_back(0x0011);
    return MethodSpec{"LL", "(Ljava/lang/Object;)Ljava/lang/Object;", code, 1, 1,
                      {"LHostFields;", "Ljava/lang/Object;"},
                      {{0, 1, "so"}}};
}

static MethodSpec makeInstanceNarrowField(const char *descriptor,
                                           const char *name,
                                           uint8_t putOpcode,
                                           uint8_t getOpcode) {
    std::vector<uint16_t> code;
    append22c(code, putOpcode, 2, 1, 0);
    append22c(code, getOpcode, 0, 1, 0);
    code.push_back(0x000f);
    return MethodSpec{"ILI", "(LHostFields;I)I", code, 3, 2,
                      {"LHostFields;", descriptor}, {{0, 1, name}}};
}

static MethodSpec makeStaticNarrowField(const char *descriptor,
                                         const char *name,
                                         uint8_t putOpcode,
                                         uint8_t getOpcode) {
    std::vector<uint16_t> code;
    append21c(code, putOpcode, 0, 0);
    append21c(code, getOpcode, 0, 0);
    code.push_back(0x000f);
    return MethodSpec{"II", "(I)I", code, 1, 1,
                      {"LHostFields;", descriptor}, {{0, 1, name}}};
}


static MethodSpec makeNewArray(const std::string &descriptor) {
    std::vector<uint16_t> code;
    appendNewArray(code, 0, 1, 1);
    code.push_back(0x0011); // return-object v0
    return MethodSpec{"LI", "(I)" + descriptor, code, 2, 1,
                      {"LHostOpcodeTest;", descriptor}};
}

static MethodSpec makeArrayLength(const std::string &descriptor) {
    std::vector<uint16_t> code;
    appendNewArray(code, 0, 2, 1);
    append12(code, 0x21, 1, 0);
    code.push_back(0x010f); // return v1
    return MethodSpec{"II", "(I)I", code, 3, 1,
                      {"LHostOpcodeTest;", descriptor}};
}

static MethodSpec makeNullArrayLength() {
    std::vector<uint16_t> code;
    append12(code, 0x21, 0, 1);
    code.push_back(0x000f);
    return MethodSpec{"IL", "([I)I", code, 2, 1,
                      {"LHostOpcodeTest;", "[I"}};
}

static MethodSpec makeNarrowArrayRoundTrip(const std::string &descriptor,
                                            uint8_t aputOpcode,
                                            uint8_t agetOpcode,
                                            const int16_t values[3],
                                            int selectedIndex) {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 3); // length
    appendNewArray(code, 1, 0, 1);
    for (int i = 0; i < 3; i++) {
        append21s(code, 0x13, 2, values[i]);
        append12(code, 0x12, 3, i);
        append23(code, aputOpcode, 2, 1, 3);
    }
    append12(code, 0x12, 3, selectedIndex);
    append23(code, agetOpcode, 4, 1, 3);
    code.push_back(0x040f); // return v4
    return MethodSpec{"I", "()I", code, 5, 0,
                      {"LHostOpcodeTest;", descriptor}};
}

static MethodSpec makeLongArrayRoundTrip(int selectedIndex) {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 3);
    appendNewArray(code, 1, 0, 1);
    for (int i = 0; i < 3; i++) {
        append12(code, 0x12, 2, i);
        append23(code, 0x4c, 4 + i * 2, 1, 2); // aput-wide
    }
    append12(code, 0x12, 2, selectedIndex);
    append23(code, 0x45, 0, 1, 2); // aget-wide
    code.push_back(0x0010); // return-wide v0
    return MethodSpec{"JJJJ", "(JJJ)J", code, 10, 6,
                      {"LHostOpcodeTest;", "[J"}};
}

static MethodSpec makeObjectArrayRoundTrip(int selectedIndex) {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 3);
    appendNewArray(code, 1, 0, 1);
    appendConstClass(code, 2, 2); // java/lang/Object Class reference
    for (int i = 0; i < 3; i++) {
        append12(code, 0x12, 3, i);
        append23(code, 0x4d, 2, 1, 3); // aput-object
    }
    append12(code, 0x12, 3, selectedIndex);
    append23(code, 0x46, 4, 1, 3); // aget-object
    code.push_back(0x0411); // return-object v4
    return MethodSpec{"L", "()Ljava/lang/Object;", code, 5, 0,
                      {"LHostOpcodeTest;", "[Ljava/lang/Object;", "Ljava/lang/Object;"}};
}

static MethodSpec makeFloatArrayRoundTrip() {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 3);          // const/4 v0, 3
    appendNewArray(code, 1, 0, 1);       // new-array v1, [F
    append12(code, 0x12, 0, 0);
    append12(code, 0x01, 2, 4);          // move v2, v4
    append23(code, 0x4b, 2, 1, 0);       // aput v2, v1, v0
    append12(code, 0x12, 0, 1);
    append12(code, 0x01, 2, 5);
    append23(code, 0x4b, 2, 1, 0);
    append12(code, 0x12, 0, 2);
    append12(code, 0x01, 2, 6);
    append23(code, 0x4b, 2, 1, 0);
    append12(code, 0x12, 0, 1);
    append23(code, 0x44, 0, 1, 0);       // aget v0, v1, v0
    code.push_back(0x000f);              // return v0
    return MethodSpec{"FFFF", "(FFF)F", code, 7, 3,
                      {"LHostOpcodeTest;", "[F"}};
}

static MethodSpec makeDoubleArrayRoundTrip() {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 3);          // const/4 v0, 3
    appendNewArray(code, 1, 0, 1);       // new-array v1, [D
    append12(code, 0x12, 0, 0);
    append12(code, 0x04, 2, 6);          // move-wide v2, v6
    append23(code, 0x4c, 2, 1, 0);       // aput-wide v2, v1, v0
    append12(code, 0x12, 0, 1);
    append12(code, 0x04, 2, 8);
    append23(code, 0x4c, 2, 1, 0);
    append12(code, 0x12, 0, 2);
    append12(code, 0x04, 2, 10);
    append23(code, 0x4c, 2, 1, 0);
    append12(code, 0x12, 0, 1);
    append23(code, 0x45, 0, 1, 0);       // aget-wide v0, v1, v0
    code.push_back(0x0010);              // return-wide v0
    return MethodSpec{"DDDD", "(DDD)D", code, 12, 6,
                      {"LHostOpcodeTest;", "[D"}};
}

static MethodSpec makeFillArrayData(const std::string &descriptor,
                                    int elementWidth,
                                    int elementCount,
                                    const std::vector<uint16_t> &payloadData) {
    std::vector<uint16_t> code;
    append12(code, 0x12, 1, elementCount);
    appendNewArray(code, 0, 1, 1);
    code.push_back(0x0026);             // fill-array-data v0
    code.push_back(5);                  // payload pc8 - instruction pc3
    code.push_back(0);
    code.push_back(0x0011);             // return-object v0
    code.push_back(0);                  // alignment nop
    code.push_back(0x0300);             // fill-array-data-payload
    code.push_back(static_cast<uint16_t>(elementWidth));
    code.push_back(static_cast<uint16_t>(elementCount));
    code.push_back(static_cast<uint16_t>(elementCount >> 16));
    code.insert(code.end(), payloadData.begin(), payloadData.end());
    return MethodSpec{"L", "()" + descriptor, code, 2, 0,
                      {"LHostOpcodeTest;", descriptor}};
}

static MethodSpec makeIntBoundsTest() {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 1);
    appendNewArray(code, 1, 0, 1);
    append23(code, 0x44, 0, 1, 2); // aget v0, v1, v2
    code.push_back(0x000f);
    return MethodSpec{"II", "(I)I", code, 3, 1,
                      {"LHostOpcodeTest;", "[I"}};
}

static MethodSpec makeLongBoundsTest() {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 1);
    appendNewArray(code, 1, 0, 1);
    append23(code, 0x45, 0, 1, 3); // aget-wide v0, v1, v3
    code.push_back(0x0010);
    return MethodSpec{"JI", "(I)J", code, 4, 1,
                      {"LHostOpcodeTest;", "[J"}};
}

static MethodSpec makeObjectBoundsTest() {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 1);
    appendNewArray(code, 1, 0, 1);
    append23(code, 0x46, 0, 1, 2); // aget-object v0, v1, v2
    code.push_back(0x0011);
    return MethodSpec{"LI", "(I)Ljava/lang/Object;", code, 3, 1,
                      {"LHostOpcodeTest;", "[Ljava/lang/Object;"}};
}

static MethodSpec makeNullAget() {
    std::vector<uint16_t> code;
    append23(code, 0x44, 0, 1, 2);
    code.push_back(0x000f);
    return MethodSpec{"ILI", "([II)I", code, 3, 2,
                      {"LHostOpcodeTest;", "[I"}};
}

static MethodSpec makeNullAput() {
    std::vector<uint16_t> code;
    append12(code, 0x12, 1, 0);
    append23(code, 0x4b, 3, 2, 1);
    code.push_back(0x000e); // return-void
    return MethodSpec{"VLI", "([II)V", code, 4, 2,
                      {"LHostOpcodeTest;", "[I"}};
}

static MethodSpec makeReturnVoidStops() {
    std::vector<uint16_t> code;
    code.push_back(0x000e);             // return-void
    code.push_back(op12(0x27, 0, 0));   // unreachable throw v0
    return MethodSpec{"V", "()V", code, 1, 0};
}

static MethodSpec makeReturnIntStops() {
    std::vector<uint16_t> code;
    append21s(code, 0x13, 0, 42);
    code.push_back(op12(0x0f, 0, 0));   // return v0
    code.push_back(op12(0x12, 0, 0));   // unreachable const/4 v0, 0
    code.push_back(op12(0x0f, 0, 0));   // unreachable return v0
    return MethodSpec{"I", "()I", code, 1, 0};
}

static MethodSpec makeReturnWideStops() {
    std::vector<uint16_t> code;
    appendConstWide(code, 0, static_cast<int64_t>(0x1122334455667788ULL));
    code.push_back(op12(0x10, 0, 0));   // return-wide v0
    appendConstWide(code, 0, 0);        // unreachable replacement value
    code.push_back(op12(0x10, 0, 0));   // unreachable return-wide v0
    return MethodSpec{"J", "()J", code, 2, 0};
}

static MethodSpec makeReturnObjectStops() {
    std::vector<uint16_t> code;
    append12(code, 0x07, 0, 1);         // move-object v0, v1
    code.push_back(op12(0x11, 0, 0));   // return-object v0
    code.push_back(op12(0x12, 0, 0));   // unreachable const/4 v0, 0
    code.push_back(op12(0x11, 0, 0));   // unreachable return-object v0
    return MethodSpec{"LL", "(Ljava/lang/Object;)Ljava/lang/Object;", code, 2, 1};
}

static MethodSpec makeUncaughtThrowNull() {
    std::vector<uint16_t> code;
    code.push_back(op12(0x12, 0, 0));   // const/4 v0, 0
    code.push_back(op12(0x27, 0, 0));   // throw v0
    return MethodSpec{"V", "()V", code, 1, 0};
}

static MethodSpec makeCatchNullArrayLength() {
    std::vector<uint16_t> code;
    append12(code, 0x21, 0, 1);         // array-length v0, v1
    code.push_back(op12(0x0d, 0, 0));   // move-exception v0
    code.push_back(op12(0x11, 0, 0));   // return-object v0
    MethodSpec spec{"LL", "([I)Ljava/lang/Throwable;", code, 2, 1,
                    {"LHostOpcodeTest;", "[I",
                     "Ljava/lang/NullPointerException;"}};
    spec.tries.push_back(TrySpec{0, 1,
                                 "Ljava/lang/NullPointerException;", 1});
    return spec;
}

static MethodSpec makeCaughtThrowObject() {
    std::vector<uint16_t> code;
    code.push_back(static_cast<uint16_t>(0x27 | (1 << 8))); // throw v1
    code.push_back(op12(0x0d, 0, 0));   // move-exception v0
    code.push_back(op12(0x11, 0, 0));   // return-object v0
    MethodSpec spec{"LL", "(Ljava/lang/Throwable;)Ljava/lang/Throwable;",
                    code, 2, 1,
                    {"LHostOpcodeTest;", "Ljava/lang/Throwable;",
                     "Ljava/lang/RuntimeException;"}};
    spec.tries.push_back(TrySpec{0, 1, "Ljava/lang/RuntimeException;", 1});
    return spec;
}

static MethodSpec makeFilledNewArray(bool range) {
    std::vector<uint16_t> code;
    append12(code, 0x12, 0, 1);
    append12(code, 0x12, 1, 2);
    append12(code, 0x12, 2, 3);
    if (range) {
        code.push_back(0x0325); // A=3 words, range starts at v0
        code.push_back(1);      // [I type index
        code.push_back(0);      // C=v0
    } else {
        code.push_back(0x3024); // A=3 words, G=0
        code.push_back(1);      // [I type index
        code.push_back(0x0210); // C=v0,D=v1,E=v2,F=v0
    }
    code.push_back(0x000c);     // move-result-object v0
    code.push_back(0x0011);     // return-object v0
    return MethodSpec{"L", "()[I", code, 3, 0,
                      {"LHostOpcodeTest;", "[I"}};
}


static JavaVM *g_vm = nullptr;
static JNIEnv *g_env = nullptr;
static jclass gFieldFixture = nullptr;

static void classU1(std::vector<uint8_t> &out, uint8_t value) {
    out.push_back(value);
}
static void classU2(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}
static void classU4(std::vector<uint8_t> &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}
static void classUtf8(std::vector<uint8_t> &out, const char *text) {
    const size_t length = strlen(text);
    classU1(out, 1);
    classU2(out, static_cast<uint16_t>(length));
    out.insert(out.end(), text, text + length);
}

static bool ensureFieldFixture() {
    if (gFieldFixture) return true;
    jclass existing = g_env->FindClass("HostFields");
    if (existing) {
        gFieldFixture = static_cast<jclass>(g_env->NewGlobalRef(existing));
        g_env->DeleteLocalRef(existing);
        return gFieldFixture != nullptr;
    }
    if (g_env->ExceptionCheck()) g_env->ExceptionClear();

    /**
     * A minimal Java 8 classfile with public instance/static int, long, and
     * Object fields. Defining it in the host JVM makes field tests independent
     * of implementation-private JDK fields.
     */
    std::vector<uint8_t> cls;
    classU4(cls, 0xcafebabeu);
    classU2(cls, 0);                  // minor
    classU2(cls, 52);                 // major
    classU2(cls, 31);                 // constant_pool_count
    classU1(cls, 7); classU2(cls, 2); // #1 Class HostFields
    classUtf8(cls, "HostFields");     // #2
    classU1(cls, 7); classU2(cls, 4); // #3 Class java/lang/Object
    classUtf8(cls, "java/lang/Object"); // #4
    classUtf8(cls, "<init>");         // #5
    classUtf8(cls, "()V");            // #6
    classU1(cls, 12); classU2(cls, 5); classU2(cls, 6); // #7 NameAndType
    classU1(cls, 10); classU2(cls, 3); classU2(cls, 7); // #8 Methodref
    classUtf8(cls, "i");              // #9
    classUtf8(cls, "I");              // #10
    classUtf8(cls, "l");              // #11
    classUtf8(cls, "J");              // #12
    classUtf8(cls, "o");              // #13
    classUtf8(cls, "Ljava/lang/Object;"); // #14
    classUtf8(cls, "si");             // #15
    classUtf8(cls, "sl");             // #16
    classUtf8(cls, "so");             // #17
    classUtf8(cls, "Code");            // #18
    classUtf8(cls, "z");               // #19
    classUtf8(cls, "Z");               // #20
    classUtf8(cls, "b");               // #21
    classUtf8(cls, "B");               // #22
    classUtf8(cls, "c");               // #23
    classUtf8(cls, "C");               // #24
    classUtf8(cls, "s");               // #25
    classUtf8(cls, "S");               // #26
    classUtf8(cls, "sz");              // #27
    classUtf8(cls, "sb");              // #28
    classUtf8(cls, "sc");              // #29
    classUtf8(cls, "ss");              // #30

    classU2(cls, 0x0021);              // public + super
    classU2(cls, 1); classU2(cls, 3);  // this_class, super_class
    classU2(cls, 0);                   // interfaces_count
    classU2(cls, 14);                  // fields_count
    auto field = [&cls](uint16_t access, uint16_t name, uint16_t desc) {
        classU2(cls, access); classU2(cls, name); classU2(cls, desc); classU2(cls, 0);
    };
    field(0x0001, 9, 10);              // public int i
    field(0x0001, 11, 12);             // public long l
    field(0x0001, 13, 14);             // public Object o
    field(0x0009, 15, 10);             // public static int si
    field(0x0009, 16, 12);             // public static long sl
    field(0x0009, 17, 14);             // public static Object so
    field(0x0001, 19, 20);             // public boolean z
    field(0x0001, 21, 22);             // public byte b
    field(0x0001, 23, 24);             // public char c
    field(0x0001, 25, 26);             // public short s
    field(0x0009, 27, 20);             // public static boolean sz
    field(0x0009, 28, 22);             // public static byte sb
    field(0x0009, 29, 24);             // public static char sc
    field(0x0009, 30, 26);             // public static short ss

    classU2(cls, 1);                   // methods_count
    classU2(cls, 0x0001); classU2(cls, 5); classU2(cls, 6); classU2(cls, 1);
    classU2(cls, 18); classU4(cls, 17); // Code attribute
    classU2(cls, 1); classU2(cls, 1); classU4(cls, 5);
    classU1(cls, 0x2a);                 // aload_0
    classU1(cls, 0xb7); classU2(cls, 8); // invokespecial Object.<init>
    classU1(cls, 0xb1);                 // return
    classU2(cls, 0); classU2(cls, 0);  // exception table / attributes
    classU2(cls, 0);                   // class attributes_count

    jclass defined = g_env->DefineClass(
            "HostFields", nullptr,
            reinterpret_cast<const jbyte *>(cls.data()),
            static_cast<jsize>(cls.size()));
    if (!defined || g_env->ExceptionCheck()) {
        if (g_env->ExceptionCheck()) g_env->ExceptionClear();
        return false;
    }
    gFieldFixture = static_cast<jclass>(g_env->NewGlobalRef(defined));
    g_env->DeleteLocalRef(defined);
    return gFieldFixture != nullptr;
}

static jobject newFieldFixtureObject() {
    jmethodID ctor = g_env->GetMethodID(gFieldFixture, "<init>", "()V");
    return ctor ? g_env->NewObject(gFieldFixture, ctor) : nullptr;
}

struct RunResult {
    VmResult result{};
    bool pendingException = false;
    bool arithmeticException = false;
    bool nullPointerException = false;
    bool arrayBoundsException = false;
    bool resultIsGlobal = false;
};

static RunResult run(const MethodSpec &spec, const jvalue *args, bool expectException) {
    std::vector<uint8_t> blob = makeVmc(spec);
    VmpFile file;
    if (!file.open(blob.data(), blob.size())) {
        fprintf(stderr, "VMP test setup failed: VMC did not open\n");
        std::exit(2);
    }
    const VmMethod *method = file.getMethod(0);
    const char *actualShorty = file.getMethodShorty(0);
    const char *actualSignature = file.getMethodSig(0);
    if (!method || !actualShorty || !actualSignature ||
            spec.shorty != actualShorty || spec.signature != actualSignature ||
            method->regs != static_cast<int>(spec.registers) ||
            method->ins != static_cast<int>(spec.incoming) ||
            !file.getInsns(method) || method->insns_size !=
            static_cast<int>(spec.insns.size())) {
        fprintf(stderr, "VMP test setup failed: method metadata/code mismatch\n");
        std::exit(2);
    }
    RunResult out;
    out.result = vmInterpret(g_env, nullptr, &file, method, args, true);
    out.pendingException = g_env->ExceptionCheck() == JNI_TRUE;
    if (out.pendingException) {
        jthrowable thrown = g_env->ExceptionOccurred();
        g_env->ExceptionClear();
        jclass arithmetic = g_env->FindClass("java/lang/ArithmeticException");
        jclass nullPointer = g_env->FindClass("java/lang/NullPointerException");
        jclass arrayBounds = g_env->FindClass("java/lang/ArrayIndexOutOfBoundsException");
        out.arithmeticException = thrown && arithmetic &&
                g_env->IsInstanceOf(thrown, arithmetic) == JNI_TRUE;
        out.nullPointerException = thrown && nullPointer &&
                g_env->IsInstanceOf(thrown, nullPointer) == JNI_TRUE;
        out.arrayBoundsException = thrown && arrayBounds &&
                g_env->IsInstanceOf(thrown, arrayBounds) == JNI_TRUE;
        if (arithmetic) g_env->DeleteLocalRef(arithmetic);
        if (nullPointer) g_env->DeleteLocalRef(nullPointer);
        if (arrayBounds) g_env->DeleteLocalRef(arrayBounds);
        if (thrown) g_env->DeleteLocalRef(thrown);
    }
    if (!out.pendingException && !spec.shorty.empty() &&
            spec.shorty[0] == 'L' && out.result.value.l) {
        jobject global = g_env->NewGlobalRef(out.result.value.l);
        if (global) {
            g_env->DeleteLocalRef(out.result.value.l);
            out.result.value.l = global;
            out.resultIsGlobal = true;
        }
    }
    if (out.pendingException != expectException) {
        fprintf(stderr, "unexpected exception state (expected=%d actual=%d)\n",
                expectException ? 1 : 0, out.pendingException ? 1 : 0);
    }
    if (expectException && !out.arithmeticException &&
            !out.nullPointerException && !out.arrayBoundsException) {
        fprintf(stderr, "unexpected exception type\n");
    }
    return out;
}

static int passed = 0;
static int failed = 0;
static int skipped = 0;

static void pass(const std::string &name) {
    passed++;
    printf("[PASS] %s\n", name.c_str());
}

static void fail(const std::string &name, const std::string &detail) {
    failed++;
    printf("[FAIL] %s\n       %s\n", name.c_str(), detail.c_str());
}

static void checkInt(const std::string &name, const MethodSpec &spec,
                     const jvalue *args, int32_t expected, bool exception = false) {
    const RunResult actual = run(spec, args, exception);
    if (exception == actual.pendingException &&
        (!exception || actual.arithmeticException) &&
        (exception || actual.result.value.i == expected)) {
        pass(name);
    } else {
        fail(name, exception ? "expected ArithmeticException" :
             "expected=" + std::to_string(expected) +
             " actual=" + std::to_string(actual.result.value.i));
    }
}

static void checkLong(const std::string &name, const MethodSpec &spec,
                      const jvalue *args, int64_t expected, bool exception = false) {
    const RunResult actual = run(spec, args, exception);
    if (exception == actual.pendingException &&
        (!exception || actual.arithmeticException) &&
        (exception || actual.result.value.j == expected)) {
        pass(name);
    } else {
        fail(name, exception ? "expected ArithmeticException" :
             "expected=" + std::to_string(expected) +
             " actual=" + std::to_string(actual.result.value.j));
    }
}

static void checkFloat(const std::string &name, const MethodSpec &spec,
                       const jvalue *args, float expected) {
    RunResult actual = run(spec, args, false);
    uint32_t expectedBits = 0;
    memcpy(&expectedBits, &expected, sizeof(expectedBits));
    const uint32_t actualBits = static_cast<uint32_t>(actual.result.value.i);
    if (!actual.pendingException && actualBits == expectedBits) {
        pass(name);
    } else {
        fail(name, "unexpected float result");
    }
}

static void checkFloatApprox(const std::string &name, const MethodSpec &spec,
                             const jvalue *args, float expected,
                             float tolerance = 1.0e-6f) {
    RunResult actual = run(spec, args, false);
    uint32_t actualBits = static_cast<uint32_t>(actual.result.value.i);
    float actualValue = 0.0f;
    memcpy(&actualValue, &actualBits, sizeof(actualValue));
    bool valid = !actual.pendingException;
    if (valid && std::isnan(expected)) {
        valid = std::isnan(actualValue);
    } else if (valid && std::isinf(expected)) {
        valid = std::isinf(actualValue) &&
                std::signbit(actualValue) == std::signbit(expected);
    } else if (valid && expected == 0.0f) {
        valid = actualValue == 0.0f &&
                std::signbit(actualValue) == std::signbit(expected);
    } else if (valid) {
        valid = std::fabs(actualValue - expected) <= tolerance;
    }
    if (valid) pass(name);
    else fail(name, "unexpected float result");
}

static void checkDouble(const std::string &name, const MethodSpec &spec,
                        const jvalue *args, double expected) {
    RunResult actual = run(spec, args, false);
    uint64_t expectedBits = 0;
    memcpy(&expectedBits, &expected, sizeof(expectedBits));
    if (!actual.pendingException &&
            static_cast<uint64_t>(actual.result.value.j) == expectedBits) {
        pass(name);
    } else {
        fail(name, "unexpected double result");
    }
}

static void checkDoubleApprox(const std::string &name, const MethodSpec &spec,
                              const jvalue *args, double expected,
                              double tolerance = 1.0e-12) {
    RunResult actual = run(spec, args, false);
    uint64_t actualBits = static_cast<uint64_t>(actual.result.value.j);
    double actualValue = 0.0;
    memcpy(&actualValue, &actualBits, sizeof(actualValue));
    bool valid = !actual.pendingException;
    if (valid && std::isnan(expected)) {
        valid = std::isnan(actualValue);
    } else if (valid && std::isinf(expected)) {
        valid = std::isinf(actualValue) &&
                std::signbit(actualValue) == std::signbit(expected);
    } else if (valid && expected == 0.0) {
        valid = actualValue == 0.0 &&
                std::signbit(actualValue) == std::signbit(expected);
    } else if (valid) {
        valid = std::fabs(actualValue - expected) <= tolerance;
    }
    if (valid) pass(name);
    else fail(name, "unexpected double result");
}
static void checkException(const std::string &name, const MethodSpec &spec,
                           const jvalue *args, bool nullPointer,
                           bool arrayBounds) {
    const RunResult actual = run(spec, args, true);
    const bool correct = actual.pendingException &&
            (nullPointer == actual.nullPointerException) &&
            (arrayBounds == actual.arrayBoundsException) &&
            !actual.arithmeticException;
    if (correct) {
        pass(name);
    } else {
        fail(name, "unexpected exception class");
    }
}

static void checkVoid(const std::string &name, const MethodSpec &spec,
                      const jvalue *args) {
    const RunResult actual = run(spec, args, false);
    if (!actual.pendingException && !actual.result.exception) {
        pass(name);
    } else {
        fail(name, "return-void did not terminate normally");
    }
}

static void checkFpInt(const std::string &name, const MethodSpec &spec,
                       const jvalue *args, int32_t expected) {
    checkInt(name, spec, args, expected, false);
}

static void checkFpLong(const std::string &name, const MethodSpec &spec,
                        const jvalue *args, int64_t expected) {
    checkLong(name, spec, args, expected, false);
}
static void releaseResultObject(RunResult &actual) {
    if (!actual.result.value.l) return;
    if (actual.resultIsGlobal)
        g_env->DeleteGlobalRef(actual.result.value.l);
    else
        g_env->DeleteLocalRef(actual.result.value.l);
    actual.result.value.l = nullptr;
    actual.resultIsGlobal = false;
}

static void checkFilledArray(const std::string &name,
                             const MethodSpec &spec,
                             const std::string &descriptor,
                             const std::vector<int64_t> &expected) {
    RunResult actual = run(spec, nullptr, false);
    jobject value = actual.result.value.l;
    jclass arrayClass = g_env->FindClass(descriptor.c_str());
    bool valid = !actual.pendingException && value && arrayClass &&
            g_env->IsInstanceOf(value, arrayClass) == JNI_TRUE &&
            g_env->GetArrayLength(static_cast<jarray>(value)) ==
                    static_cast<jsize>(expected.size());
    if (valid && descriptor == "[B") {
        std::vector<jbyte> values(expected.size());
        g_env->GetByteArrayRegion((jbyteArray)value, 0, values.size(), values.data());
        for (size_t i = 0; i < values.size(); i++) valid &= values[i] == expected[i];
    } else if (valid && descriptor == "[S") {
        std::vector<jshort> values(expected.size());
        g_env->GetShortArrayRegion((jshortArray)value, 0, values.size(), values.data());
        for (size_t i = 0; i < values.size(); i++) valid &= values[i] == expected[i];
    } else if (valid && descriptor == "[C") {
        std::vector<jchar> values(expected.size());
        g_env->GetCharArrayRegion((jcharArray)value, 0, values.size(), values.data());
        for (size_t i = 0; i < values.size(); i++) valid &= values[i] == expected[i];
    } else if (valid && descriptor == "[I") {
        std::vector<jint> values(expected.size());
        g_env->GetIntArrayRegion((jintArray)value, 0, values.size(), values.data());
        for (size_t i = 0; i < values.size(); i++) valid &= values[i] == expected[i];
    } else if (valid && descriptor == "[J") {
        std::vector<jlong> values(expected.size());
        g_env->GetLongArrayRegion((jlongArray)value, 0, values.size(), values.data());
        for (size_t i = 0; i < values.size(); i++) valid &= values[i] == expected[i];
    } else {
        valid = false;
    }
    if (arrayClass) g_env->DeleteLocalRef(arrayClass);
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "fill-array-data contents/type mismatch");
}

static void checkArrayCreation(const std::string &name, const MethodSpec &spec,
                               const jvalue *args, int expectedLength,
                               const std::string &descriptor) {
    RunResult actual = run(spec, args, false);
    jobject value = actual.result.value.l;
    jclass arrayClass = descriptor.empty() ? nullptr :
            g_env->FindClass(descriptor.c_str());
    const bool valid = !actual.pendingException && value && arrayClass &&
            g_env->IsInstanceOf(value, arrayClass) == JNI_TRUE &&
            g_env->GetArrayLength(static_cast<jarray>(value)) == expectedLength;
    if (arrayClass) g_env->DeleteLocalRef(arrayClass);
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "array creation/length/type mismatch");
}

static void checkObjectRoundTrip(const std::string &name, const MethodSpec &spec,
                                 const jvalue *args) {
    RunResult actual = run(spec, args, false);
    jobject value = actual.result.value.l;
    jclass classClass = g_env->FindClass("java/lang/Class");
    jclass expected = g_env->FindClass("java/lang/Object");
    const bool valid = !actual.pendingException && value && classClass && expected &&
            g_env->IsInstanceOf(value, classClass) == JNI_TRUE &&
            g_env->IsSameObject(value, expected) == JNI_TRUE;
    if (classClass) g_env->DeleteLocalRef(classClass);
    if (expected) g_env->DeleteLocalRef(expected);
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "object array round-trip returned the wrong reference");
}

static void checkIntArrayContents(const std::string &name,
                                   const MethodSpec &spec,
                                   const std::vector<jint> &expected) {
    RunResult actual = run(spec, nullptr, false);
    jobject value = actual.result.value.l;
    jclass arrayClass = g_env->FindClass("[I");
    std::vector<jint> actualValues(expected.size());
    bool valid = !actual.pendingException && value && arrayClass &&
            g_env->IsInstanceOf(value, arrayClass) == JNI_TRUE &&
            g_env->GetArrayLength(static_cast<jarray>(value)) ==
                    static_cast<jsize>(expected.size());
    if (valid) {
        g_env->GetIntArrayRegion(static_cast<jintArray>(value), 0,
                                 static_cast<jsize>(actualValues.size()),
                                 actualValues.data());
        valid = actualValues == expected && !g_env->ExceptionCheck();
    }
    if (arrayClass) g_env->DeleteLocalRef(arrayClass);
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "int array contents/length mismatch");
}

static void checkReturnedObjectIdentity(const std::string &name,
                                        const MethodSpec &spec,
                                        const jvalue *args,
                                        jobject expected) {
    RunResult actual = run(spec, args, false);
    jobject value = actual.result.value.l;
    const bool valid = !actual.pendingException && value && expected &&
            g_env->IsSameObject(value, expected) == JNI_TRUE;
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "returned object does not match expected reference");
}

static void checkReturnedObjectClass(const std::string &name,
                                     const MethodSpec &spec,
                                     const jvalue *args,
                                     const char *className) {
    RunResult actual = run(spec, args, false);
    jobject value = actual.result.value.l;
    jclass expected = g_env->FindClass(className);
    const bool valid = !actual.pendingException && value && expected &&
            g_env->IsInstanceOf(value, expected) == JNI_TRUE;
    if (expected) g_env->DeleteLocalRef(expected);
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "caught exception object has the wrong class");
}

static void checkStringResult(const std::string &name, const MethodSpec &spec,
                              const jvalue *args, const char *expected) {
    RunResult actual = run(spec, args, false);
    jstring value = static_cast<jstring>(actual.result.value.l);
    const char *text = value ? g_env->GetStringUTFChars(value, nullptr) : nullptr;
    const bool valid = !actual.pendingException && text &&
            strcmp(text, expected) == 0 && !g_env->ExceptionCheck();
    if (text) g_env->ReleaseStringUTFChars(value, text);
    releaseResultObject(actual);
    if (valid) pass(name);
    else fail(name, "unexpected string return");
}

static jobject makeIntegerObject(jint value) {
    jclass clazz = g_env->FindClass("java/lang/Integer");
    if (!clazz) return nullptr;
    jmethodID ctor = g_env->GetMethodID(clazz, "<init>", "(I)V");
    jobject result = ctor ? g_env->NewObject(clazz, ctor, value) : nullptr;
    g_env->DeleteLocalRef(clazz);
    return result;
}

static jobject makeLongObject(jlong value) {
    jclass clazz = g_env->FindClass("java/lang/Long");
    if (!clazz) return nullptr;
    jmethodID ctor = g_env->GetMethodID(clazz, "<init>", "(J)V");
    jvalue arg{};
    arg.j = value;
    jobject result = ctor ? g_env->NewObjectA(clazz, ctor, &arg) : nullptr;
    g_env->DeleteLocalRef(clazz);
    return result;
}

static jobject makeRuntimeExceptionObject() {
    jclass clazz = g_env->FindClass("java/lang/RuntimeException");
    if (!clazz) return nullptr;
    jmethodID ctor = g_env->GetMethodID(clazz, "<init>", "()V");
    jobject result = ctor ? g_env->NewObject(clazz, ctor) : nullptr;
    g_env->DeleteLocalRef(clazz);
    return result;
}

static jobject makeListObject(int count) {
    jclass listClass = g_env->FindClass("java/util/ArrayList");
    if (!listClass) return nullptr;
    jmethodID ctor = g_env->GetMethodID(listClass, "<init>", "()V");
    jmethodID add = g_env->GetMethodID(listClass, "add", "(Ljava/lang/Object;)Z");
    jobject list = (ctor && add) ? g_env->NewObject(listClass, ctor) : nullptr;
    for (int i = 0; list && i < count; i++) {
        char text[32];
        snprintf(text, sizeof(text), "list-%d", i);
        jstring item = g_env->NewStringUTF(text);
        g_env->CallBooleanMethod(list, add, item);
        if (item) g_env->DeleteLocalRef(item);
        if (g_env->ExceptionCheck()) break;
    }
    if (g_env->ExceptionCheck()) {
        g_env->ExceptionClear();
        if (list) g_env->DeleteLocalRef(list);
        list = nullptr;
    }
    g_env->DeleteLocalRef(listClass);
    return list;
}

static jobject promoteTestReference(jobject local) {
    if (!local) return nullptr;
    jobject global = g_env->NewGlobalRef(local);
    g_env->DeleteLocalRef(local);
    return global;
}

static void releaseTestGlobal(jobject global) {
    if (global) g_env->DeleteGlobalRef(global);
}


static MethodSpec makeDoubleBinaryOpcode(uint8_t opcode) {
    return MethodSpec{
        "DDD", "(DD)D", op23(opcode, 0, 0, 2, 0x0010), 4, 4
    };
}

static void testDoubleBinaryOpcodes() {
    const MethodSpec add = makeDoubleBinaryOpcode(0xab);
    const MethodSpec sub = makeDoubleBinaryOpcode(0xac);
    const MethodSpec mul = makeDoubleBinaryOpcode(0xad);
    const MethodSpec div = makeDoubleBinaryOpcode(0xae);
    const MethodSpec rem = makeDoubleBinaryOpcode(0xaf);

    jvalue args[2]{};
    args[0].d = 1.5;
    args[1].d = 2.25;
    checkDoubleApprox("add-double normal", add, args, 3.75);

    args[0].d = 0.0;
    args[1].d = -0.0;
    checkDoubleApprox("add-double signed zero", add, args, 0.0);
    args[0].d = std::numeric_limits<double>::quiet_NaN();
    args[1].d = 1.0;
    checkDoubleApprox("add-double NaN", add, args,
                      std::numeric_limits<double>::quiet_NaN());

    args[0].d = -1.5;
    args[1].d = 2.25;
    checkDoubleApprox("sub-double negative", sub, args, -3.75);
    args[0].d = -0.0;
    args[1].d = 0.0;
    checkDoubleApprox("sub-double signed zero", sub, args, -0.0);
    args[0].d = std::numeric_limits<double>::infinity();
    args[1].d = std::numeric_limits<double>::infinity();
    checkDoubleApprox("sub-double infinity NaN", sub, args,
                      std::numeric_limits<double>::quiet_NaN());

    args[0].d = -1.5;
    args[1].d = 2.25;
    checkDoubleApprox("mul-double negative", mul, args, -3.375);
    args[0].d = 0.0;
    args[1].d = std::numeric_limits<double>::infinity();
    checkDoubleApprox("mul-double zero infinity NaN", mul, args,
                      std::numeric_limits<double>::quiet_NaN());
    args[0].d = std::numeric_limits<double>::infinity();
    args[1].d = -2.0;
    checkDoubleApprox("mul-double signed infinity", mul, args,
                      -std::numeric_limits<double>::infinity());

    args[0].d = 7.5;
    args[1].d = 2.5;
    checkDoubleApprox("div-double normal", div, args, 3.0);
    args[0].d = -7.5;
    args[1].d = 2.5;
    checkDoubleApprox("div-double negative", div, args, -3.0);
    args[0].d = -0.0;
    args[1].d = 2.0;
    checkDoubleApprox("div-double signed zero", div, args, -0.0);
    args[0].d = std::numeric_limits<double>::infinity();
    args[1].d = 2.0;
    checkDoubleApprox("div-double infinity", div, args,
                      std::numeric_limits<double>::infinity());
    args[0].d = 0.0;
    args[1].d = 0.0;
    checkDoubleApprox("div-double zero NaN", div, args,
                      std::numeric_limits<double>::quiet_NaN());

    args[0].d = -7.5;
    args[1].d = 2.0;
    checkDoubleApprox("rem-double negative", rem, args, -1.5);
    args[0].d = 3.5;
    args[1].d = std::numeric_limits<double>::infinity();
    checkDoubleApprox("rem-double infinity divisor", rem, args, 3.5);
    args[0].d = std::numeric_limits<double>::infinity();
    args[1].d = 2.0;
    checkDoubleApprox("rem-double infinity NaN", rem, args,
                      std::numeric_limits<double>::quiet_NaN());
    args[0].d = std::numeric_limits<double>::quiet_NaN();
    args[1].d = 2.0;
    checkDoubleApprox("rem-double NaN", rem, args,
                      std::numeric_limits<double>::quiet_NaN());
}

static MethodSpec makeFloatBinaryOpcode(uint8_t opcode) {
    return MethodSpec{
        "FFF", "(FF)F", op23(opcode, 0, 0, 1, 0x000f), 2, 2
    };
}

static void testFloatBinaryOpcodes() {
    const MethodSpec add = makeFloatBinaryOpcode(0xa6);
    const MethodSpec sub = makeFloatBinaryOpcode(0xa7);
    const MethodSpec mul = makeFloatBinaryOpcode(0xa8);
    const MethodSpec div = makeFloatBinaryOpcode(0xa9);
    const MethodSpec rem = makeFloatBinaryOpcode(0xaa);

    jvalue args[2]{};
    args[0].f = 1.5f;
    args[1].f = 2.25f;
    checkFloatApprox("add-float normal", add, args, 3.75f);

    args[0].f = 0.0f;
    args[1].f = -0.0f;
    checkFloatApprox("add-float signed zero", add, args, 0.0f);
    args[0].f = std::numeric_limits<float>::quiet_NaN();
    args[1].f = 1.0f;
    checkFloatApprox("add-float NaN", add, args,
                     std::numeric_limits<float>::quiet_NaN());

    args[0].f = -1.5f;
    args[1].f = 2.25f;
    checkFloatApprox("sub-float negative", sub, args, -3.75f);
    args[0].f = -0.0f;
    args[1].f = 0.0f;
    checkFloatApprox("sub-float signed zero", sub, args, -0.0f);
    args[0].f = std::numeric_limits<float>::infinity();
    args[1].f = std::numeric_limits<float>::infinity();
    checkFloatApprox("sub-float infinity NaN", sub, args,
                     std::numeric_limits<float>::quiet_NaN());

    args[0].f = -1.5f;
    args[1].f = 2.25f;
    checkFloatApprox("mul-float negative", mul, args, -3.375f);
    args[0].f = 0.0f;
    args[1].f = std::numeric_limits<float>::infinity();
    checkFloatApprox("mul-float zero infinity NaN", mul, args,
                     std::numeric_limits<float>::quiet_NaN());
    args[0].f = std::numeric_limits<float>::infinity();
    args[1].f = -2.0f;
    checkFloatApprox("mul-float signed infinity", mul, args,
                     -std::numeric_limits<float>::infinity());

    args[0].f = 7.5f;
    args[1].f = 2.5f;
    checkFloatApprox("div-float normal", div, args, 3.0f);
    args[0].f = -7.5f;
    args[1].f = 2.5f;
    checkFloatApprox("div-float negative", div, args, -3.0f);
    args[0].f = -0.0f;
    args[1].f = 2.0f;
    checkFloatApprox("div-float signed zero", div, args, -0.0f);
    args[0].f = std::numeric_limits<float>::infinity();
    args[1].f = 2.0f;
    checkFloatApprox("div-float infinity", div, args,
                     std::numeric_limits<float>::infinity());
    args[0].f = 0.0f;
    args[1].f = 0.0f;
    checkFloatApprox("div-float zero NaN", div, args,
                     std::numeric_limits<float>::quiet_NaN());

    args[0].f = -7.5f;
    args[1].f = 2.0f;
    checkFloatApprox("rem-float negative", rem, args, -1.5f);
    args[0].f = 3.5f;
    args[1].f = std::numeric_limits<float>::infinity();
    checkFloatApprox("rem-float infinity divisor", rem, args, 3.5f);
    args[0].f = std::numeric_limits<float>::infinity();
    args[1].f = 2.0f;
    checkFloatApprox("rem-float infinity NaN", rem, args,
                     std::numeric_limits<float>::quiet_NaN());
    args[0].f = std::numeric_limits<float>::quiet_NaN();
    args[1].f = 2.0f;
    checkFloatApprox("rem-float NaN", rem, args,
                     std::numeric_limits<float>::quiet_NaN());
}

static MethodSpec makeLongBinaryOpcode(uint8_t opcode) {
    return MethodSpec{
        "JJJ", "(JJ)J", op23(opcode, 0, 0, 2, 0x0010), 4, 4
    };
}

static void testLongBinaryOpcodes() {
    struct LongBinaryCase {
        const char *name;
        uint8_t opcode;
        int64_t left;
        int64_t right;
        int64_t expected;
    };
    const LongBinaryCase cases[] = {
        {"add-long", 0x9b,
         static_cast<int64_t>(0x1122334455667788ULL),
         static_cast<int64_t>(0x0102030405060708ULL),
         static_cast<int64_t>(0x122436485a6c7e90ULL)},
        {"sub-long", 0x9c,
         static_cast<int64_t>(0x1122334455667788ULL),
         static_cast<int64_t>(0x0102030405060708ULL),
         static_cast<int64_t>(0x1020304050607080ULL)},
        {"mul-long", 0x9d, 0x100000000LL, 7, 0x700000000LL},
        {"and-long", 0xa0, 0x55aa55aa55aa55aaLL,
         0x0f0f0f0f0f0f0f0fLL, 0x050a050a050a050aLL},
        {"or-long", 0xa1, 0x55aa55aa55aa55aaLL,
         0x0f0f0f0f0f0f0f0fLL, 0x5faf5faf5faf5fafLL},
        {"xor-long", 0xa2, 0x55aa55aa55aa55aaLL,
         0x0f0f0f0f0f0f0f0fLL, 0x5aa55aa55aa55aa5LL},
        /** Dalvik masks the long shift count to six bits: 64 becomes 0. */
        {"shl-long", 0xa3, 1, 64, 1},
        /** 65 becomes 1, preserving arithmetic right-shift sign extension. */
        {"shr-long", 0xa4, -8, 65, -4},
        /** All-ones unsigned value shifted right by two bits. */
        {"ushr-long", 0xa5, -1, 2, 0x3fffffffffffffffLL},
    };
    for (const LongBinaryCase &test : cases) {
        jvalue args[2]{};
        args[0].j = test.left;
        args[1].j = test.right;
        checkLong(test.name, makeLongBinaryOpcode(test.opcode), args,
                  test.expected);
    }
}

static MethodSpec makeIntBinaryOpcode(uint8_t opcode) {
    return MethodSpec{
        "III", "(II)I", op23(opcode, 0, 0, 1, 0x000f), 2, 2
    };
}

static void testIntBinaryOpcodes() {
    struct IntBinaryCase {
        const char *name;
        uint8_t opcode;
        int32_t left;
        int32_t right;
        int32_t expected;
    };
    const IntBinaryCase cases[] = {
        {"add-int", 0x90, INT32_MAX, 1, INT32_MIN},
        {"sub-int", 0x91, INT32_MIN, 1, INT32_MAX},
        {"mul-int", 0x92, INT32_MAX, 2, -2},
        {"and-int", 0x95, 0x55aa55aa, 0x0f0f0f0f, 0x050a050a},
        {"or-int", 0x96, 0x55aa55aa, 0x0f0f0f0f, 0x5faf5faf},
        {"xor-int", 0x97, 0x55aa55aa, 0x0f0f0f0f, 0x5aa55aa5},
        /** Dalvik masks the shift count to five bits: 32 becomes 0. */
        {"shl-int", 0x98, 1, 32, 1},
        /** 33 becomes 1, preserving arithmetic right-shift sign extension. */
        {"shr-int", 0x99, -8, 33, -4},
        /** 33 becomes 1, producing an unsigned right shift of -2 by one. */
        {"ushr-int", 0x9a, -2, 33, 0x7fffffff},
    };
    for (const IntBinaryCase &test : cases) {
        jvalue args[2]{};
        args[0].i = test.left;
        args[1].i = test.right;
        checkInt(test.name, makeIntBinaryOpcode(test.opcode), args,
                 test.expected);
    }
}

static MethodSpec makeIntTwoAddr(uint8_t opcode) {
    return MethodSpec{
        "III", "(II)I", {op12(opcode, 0, 1), op12(0x0f, 0, 0)}, 2, 2
    };
}

static MethodSpec makeLongTwoAddr(uint8_t opcode) {
    return MethodSpec{
        "JJJ", "(JJ)J", {op12(opcode, 0, 2), op12(0x10, 0, 0)}, 4, 4
    };
}

static MethodSpec makeFloatTwoAddr(uint8_t opcode) {
    return MethodSpec{
        "FFF", "(FF)F", {op12(opcode, 0, 1), op12(0x0f, 0, 0)}, 2, 2
    };
}

static MethodSpec makeDoubleTwoAddr(uint8_t opcode) {
    return MethodSpec{
        "DDD", "(DD)D", {op12(opcode, 0, 2), op12(0x10, 0, 0)}, 4, 4
    };
}

static MethodSpec makeCompareSpec(uint8_t opcode,
                                   const char *shorty,
                                   const char *signature,
                                   uint32_t registers,
                                   uint32_t incoming,
                                   int firstRegister,
                                   int secondRegister) {
    return MethodSpec{
        shorty, signature,
        op23(opcode, 0, firstRegister, secondRegister, 0x000f),
        registers, incoming
    };
}

static void testCompareOpcodes() {
    const uint8_t floatCompareOpcodes[] = {0x2d, 0x2e};
    const char *floatNames[] = {"cmpl-float", "cmpg-float"};
    for (int i = 0; i < 2; i++) {
        const bool lessNaN = i == 0;
        jvalue args[2]{};
        args[0].f = -1.5f;
        args[1].f = 2.0f;
        checkInt(std::string(floatNames[i]) + " less", makeCompareSpec(
                         floatCompareOpcodes[i], "IFF", "(FF)I", 2, 2, 0, 1),
                 args, -1);
        args[0].f = 2.0f;
        args[1].f = -1.5f;
        checkInt(std::string(floatNames[i]) + " greater", makeCompareSpec(
                         floatCompareOpcodes[i], "IFF", "(FF)I", 2, 2, 0, 1),
                 args, 1);
        args[0].f = 2.0f;
        args[1].f = 2.0f;
        checkInt(std::string(floatNames[i]) + " equal", makeCompareSpec(
                         floatCompareOpcodes[i], "IFF", "(FF)I", 2, 2, 0, 1),
                 args, 0);
        args[0].f = std::numeric_limits<float>::quiet_NaN();
        args[1].f = 2.0f;
        checkInt(std::string(floatNames[i]) + " NaN", makeCompareSpec(
                         floatCompareOpcodes[i], "IFF", "(FF)I", 2, 2, 0, 1),
                 args, lessNaN ? -1 : 1);
    }

    const uint8_t doubleCompareOpcodes[] = {0x2f, 0x30};
    const char *doubleNames[] = {"cmpl-double", "cmpg-double"};
    for (int i = 0; i < 2; i++) {
        const bool lessNaN = i == 0;
        jvalue args[2]{};
        args[0].d = -1.5;
        args[1].d = 2.0;
        checkInt(std::string(doubleNames[i]) + " less", makeCompareSpec(
                         doubleCompareOpcodes[i], "IDD", "(DD)I", 4, 4, 0, 2),
                 args, -1);
        args[0].d = 2.0;
        args[1].d = -1.5;
        checkInt(std::string(doubleNames[i]) + " greater", makeCompareSpec(
                         doubleCompareOpcodes[i], "IDD", "(DD)I", 4, 4, 0, 2),
                 args, 1);
        args[0].d = 2.0;
        args[1].d = 2.0;
        checkInt(std::string(doubleNames[i]) + " equal", makeCompareSpec(
                         doubleCompareOpcodes[i], "IDD", "(DD)I", 4, 4, 0, 2),
                 args, 0);
        args[0].d = std::numeric_limits<double>::quiet_NaN();
        args[1].d = 2.0;
        checkInt(std::string(doubleNames[i]) + " NaN", makeCompareSpec(
                         doubleCompareOpcodes[i], "IDD", "(DD)I", 4, 4, 0, 2),
                 args, lessNaN ? -1 : 1);
    }

    jvalue longArgs[2]{};
    longArgs[0].j = -9;
    longArgs[1].j = 4;
    checkInt("cmp-long less", makeCompareSpec(
                     0x31, "IJJ", "(JJ)I", 4, 4, 0, 2), longArgs, -1);
    longArgs[0].j = 9;
    longArgs[1].j = -4;
    checkInt("cmp-long greater", makeCompareSpec(
                     0x31, "IJJ", "(JJ)I", 4, 4, 0, 2), longArgs, 1);
    longArgs[0].j = 9;
    longArgs[1].j = 9;
    checkInt("cmp-long equal", makeCompareSpec(
                     0x31, "IJJ", "(JJ)I", 4, 4, 0, 2), longArgs, 0);
}

static MethodSpec makeMoveIntVariant(uint8_t opcode) {
    std::vector<uint16_t> code;
    if (opcode == 0x02) {
        code = {0x0002, 1, 0x000f};
    } else {
        code = {static_cast<uint16_t>(opcode), 0, 1, 0x000f};
    }
    return MethodSpec{"II", "(I)I", code, 2, 1};
}

static MethodSpec makeMoveWideVariant(uint8_t opcode) {
    std::vector<uint16_t> code;
    if (opcode == 0x04) {
        code = {op12(opcode, 0, 2), 0x0010};
    } else if (opcode == 0x05) {
        code = {0x0005, 2, 0x0010};
    } else {
        code = {0x0006, 0, 2, 0x0010};
    }
    return MethodSpec{"JJ", "(J)J", code, 4, 2};
}

static MethodSpec makeMoveObjectVariant(uint8_t opcode) {
    std::vector<uint16_t> code;
    if (opcode == 0x08) {
        code = {0x0008, 2, 0x0011};
    } else {
        code = {0x0009, 0, 2, 0x0011};
    }
    return MethodSpec{"LL", "(Ljava/lang/Object;)Ljava/lang/Object;", code, 3, 1};
}

static MethodSpec makeConstIntVariant(uint8_t opcode) {
    if (opcode == 0x14) {
        return MethodSpec{"I", "()I", {0x0014, 0x5678, 0x1234, 0x000f}, 1, 0};
    }
    return MethodSpec{"I", "()I", {0x0015, 0x1234, 0x000f}, 1, 0};
}

static MethodSpec makeConstWideVariant(uint8_t opcode) {
    if (opcode == 0x16) {
        return MethodSpec{"J", "()J", {0x0016, static_cast<uint16_t>(-1234), 0x0010}, 2, 0};
    }
    if (opcode == 0x17) {
        return MethodSpec{"J", "()J", {0x0017, 0x5678, 0x1234, 0x0010}, 2, 0};
    }
    return MethodSpec{"J", "()J", {0x0019, 0x1234, 0x0010}, 2, 0};
}

static MethodSpec makeConstStringVariant(bool jumbo) {
    std::vector<uint16_t> code;
    if (jumbo) code = {0x001b, 5, 0, 0x0011};
    else code = {0x001a, 5, 0x0011};
    MethodSpec spec{"L", "()Ljava/lang/String;", code, 1, 0};
    spec.stringLiterals.push_back("const-string-value");
    return spec;
}

static void testMoveConstOpcodes() {
    const int32_t moveValue = 0x12345678;
    jvalue intArg{};
    intArg.i = moveValue;
    checkInt("move/from16", makeMoveIntVariant(0x02), &intArg, moveValue);
    checkInt("move/16", makeMoveIntVariant(0x03), &intArg, moveValue);

    const int64_t wideValue = static_cast<int64_t>(0x1122334455667788ULL);
    jvalue wideArg{};
    wideArg.j = wideValue;
    checkLong("move-wide", makeMoveWideVariant(0x04), &wideArg, wideValue);
    checkLong("move-wide/from16", makeMoveWideVariant(0x05), &wideArg, wideValue);
    checkLong("move-wide/16", makeMoveWideVariant(0x06), &wideArg, wideValue);

    jobject object = makeIntegerObject(99);
    if (!object) {
        fail("move-object fixture setup", "Integer object creation failed");
        if (g_env->ExceptionCheck()) g_env->ExceptionClear();
        return;
    }
    jvalue objectArg{};
    objectArg.l = object;
    checkReturnedObjectIdentity("move-object/from16", makeMoveObjectVariant(0x08),
                               &objectArg, object);
    checkReturnedObjectIdentity("move-object/16", makeMoveObjectVariant(0x09),
                               &objectArg, object);
    g_env->DeleteLocalRef(object);

    checkInt("const", makeConstIntVariant(0x14), nullptr, 0x12345678);
    checkInt("const/high16", makeConstIntVariant(0x15), nullptr, 0x12340000);
    checkLong("const-wide/16", makeConstWideVariant(0x16), nullptr, -1234);
    checkLong("const-wide/32", makeConstWideVariant(0x17), nullptr,
              static_cast<int64_t>(0x12345678));
    checkLong("const-wide/high16", makeConstWideVariant(0x19), nullptr,
              static_cast<int64_t>(0x1234000000000000ULL));
    checkStringResult("const-string", makeConstStringVariant(false), nullptr,
                      "const-string-value");
    checkStringResult("const-string/jumbo", makeConstStringVariant(true), nullptr,
                      "const-string-value");
}

static void testTwoAddrOpcodes() {
    struct IntCase { uint8_t opcode; int32_t a; int32_t b; int32_t expected; };
    const IntCase intCases[] = {
        {0xb0, 17, 5, 22},
        {0xb1, 17, 5, 12},
        {0xb2, 17, 5, 85},
        {0xb3, 17, 5, 3},
        {0xb4, 17, 5, 2},
        {0xb5, 0x36, 0x0f, 0x06},
        {0xb6, 0x36, 0x0f, 0x3f},
        {0xb7, 0x36, 0x0f, 0x39},
        {0xb8, 1, 3, 8},
        {0xb9, -16, 2, -4},
        {0xba, -16, 2, 0x3ffffffc},
    };
    for (const IntCase &test : intCases) {
        jvalue args[2]{};
        args[0].i = test.a;
        args[1].i = test.b;
        checkInt("int /2addr opcode", makeIntTwoAddr(test.opcode), args,
                 test.expected);
    }

    struct LongCase { uint8_t opcode; int64_t a; int64_t b; int64_t expected; };
    const LongCase longCases[] = {
        {0xbb, 10000000000LL, 7, 10000000007LL},
        {0xbc, 10000000000LL, 7, 9999999993LL},
        {0xbd, 17, 5, 85},
        {0xbe, 17, 5, 3},
        {0xbf, 17, 5, 2},
        {0xc0, 0x36, 0x0f, 0x06},
        {0xc1, 0x36, 0x0f, 0x3f},
        {0xc2, 0x36, 0x0f, 0x39},
        {0xc3, 1, 3, 8},
        {0xc4, -16, 2, -4},
        {0xc5, -16, 2, 0x3ffffffffffffffcLL},
    };
    for (const LongCase &test : longCases) {
        jvalue args[2]{};
        args[0].j = test.a;
        args[1].j = test.b;
        checkLong("long /2addr opcode", makeLongTwoAddr(test.opcode), args,
                  test.expected);
    }

    struct FloatCase { uint8_t opcode; float a; float b; float expected; };
    const FloatCase floatCases[] = {
        {0xc6, 3.5f, 1.25f, 4.75f},
        {0xc7, 3.5f, 1.25f, 2.25f},
        {0xc8, 3.5f, 1.25f, 4.375f},
        {0xc9, 5.0f, 2.0f, 2.5f},
        {0xca, 5.5f, 2.0f, 1.5f},
    };
    for (const FloatCase &test : floatCases) {
        jvalue args[2]{};
        args[0].f = test.a;
        args[1].f = test.b;
        checkFloat("float /2addr opcode", makeFloatTwoAddr(test.opcode), args,
                   test.expected);
    }

    struct DoubleCase { uint8_t opcode; double a; double b; double expected; };
    const DoubleCase doubleCases[] = {
        {0xcb, 3.5, 1.25, 4.75},
        {0xcc, 3.5, 1.25, 2.25},
        {0xcd, 3.5, 1.25, 4.375},
        {0xce, 5.0, 2.0, 2.5},
        {0xcf, 5.5, 2.0, 1.5},
    };
    for (const DoubleCase &test : doubleCases) {
        jvalue args[2]{};
        args[0].d = test.a;
        args[1].d = test.b;
        checkDouble("double /2addr opcode", makeDoubleTwoAddr(test.opcode), args,
                    test.expected);
    }
}

static MethodSpec makeIntLiteralOpcode(uint8_t opcode, bool lit8,
                                           int8_t literal8, int16_t literal16) {
    const std::vector<uint16_t> code = lit8
            ? op22b(opcode, 0, 0, literal8)
            : op22s(opcode, 0, 0, literal16);
    return MethodSpec{"II", "(I)I", code, 1, 1};
}

static void testIntLiteralOpcodes() {
    struct LiteralCase {
        const char *name;
        uint8_t opcode;
        int8_t literal8;
        int16_t literal16;
        int32_t input;
        int32_t expected;
    };
    const LiteralCase lit8Cases[] = {
        {"add-int/lit8", 0xd8, 5, 0, 22, 27},
        {"rsub-int/lit8", 0xd9, 5, 0, 22, -17},
        {"mul-int/lit8", 0xda, 5, 0, 22, 110},
        {"and-int/lit8", 0xdd, 0x0f, 0, 0x55aa55aa, 0x0000000a},
        {"or-int/lit8", 0xde, 0x0f, 0, 0x55aa55aa, 0x55aa55af},
        {"xor-int/lit8", 0xdf, 0x0f, 0, 0x55aa55aa, 0x55aa55a5},
        {"shl-int/lit8", 0xe0, 32, 0, 1, 1},
        {"shr-int/lit8", 0xe1, 33, 0, -8, -4},
        {"ushr-int/lit8", 0xe2, 33, 0, -2, 0x7fffffff},
    };
    for (const LiteralCase &test : lit8Cases) {
        jvalue arg{};
        arg.i = test.input;
        checkInt(test.name,
                 makeIntLiteralOpcode(test.opcode, true,
                                      test.literal8, test.literal16),
                 &arg, test.expected);
    }

    const LiteralCase lit16Cases[] = {
        {"add-int/lit16", 0xd0, 0, 300, 22, 322},
        {"rsub-int", 0xd1, 0, 300, 22, 278},
        {"mul-int/lit16", 0xd2, 0, 300, 22, 6600},
        {"and-int/lit16", 0xd5, 0, 0x0f0f, 0x55aa55aa, 0x0000050a},
        {"or-int/lit16", 0xd6, 0, 0x0f0f, 0x55aa55aa, 0x55aa5faf},
        {"xor-int/lit16", 0xd7, 0, 0x0f0f, 0x55aa55aa, 0x55aa5aa5},
    };
    for (const LiteralCase &test : lit16Cases) {
        jvalue arg{};
        arg.i = test.input;
        checkInt(test.name,
                 makeIntLiteralOpcode(test.opcode, false,
                                      test.literal8, test.literal16),
                 &arg, test.expected);
    }
}

static void testIntegerOpcodes() {
    struct IntOp { const char *name; uint8_t opcode; bool literal8; bool literal16; };
    const IntOp intOps[] = {
        {"div-int", 0x93, false, false},
        {"rem-int", 0x94, false, false},
        {"div-int/2addr", 0xb3, false, false},
        {"rem-int/2addr", 0xb4, false, false},
        {"div-int/lit8", 0xdb, true, false},
        {"rem-int/lit8", 0xdc, true, false},
        {"div-int/lit16", 0xd3, false, true},
        {"rem-int/lit16", 0xd4, false, true},
    };
    for (const IntOp &op : intOps) {
        const bool rem = op.opcode == 0x94 || op.opcode == 0xb4 ||
                         op.opcode == 0xdc || op.opcode == 0xd4;
        MethodSpec spec{"III", "(II)I", {}, 2, 2};
        jvalue args[2]{};
        if (op.literal8 || op.literal16) {
            spec = MethodSpec{"II", "(I)I", {}, 1, 1};
            args[0].i = 22;
            spec.insns = op.literal8 ? op22b(op.opcode, 0, 0, 5)
                                     : op22s(op.opcode, 0, 0, 5);
            checkInt(std::string(op.name) + " normal", spec, args,
                     rem ? 2 : 4);
            args[0].i = -22;
            checkInt(std::string(op.name) + " negative", spec, args,
                     rem ? -2 : -4);
            args[0].i = INT32_MIN;
            if (op.literal8 || op.literal16) {
                spec.insns = op.literal8 ? op22b(op.opcode, 0, 0, -1)
                                         : op22s(op.opcode, 0, 0, -1);
                checkInt(std::string(op.name) + " MIN/-1", spec, args,
                         rem ? 0 : INT32_MIN);
            }
            args[0].i = 7;
            spec.insns = op.literal8 ? op22b(op.opcode, 0, 0, 0)
                                     : op22s(op.opcode, 0, 0, 0);
            checkInt(std::string(op.name) + " zero", spec, args, 0, true);
        } else {
            args[0].i = 22; args[1].i = 5;
            spec.insns = (op.opcode == 0xb3 || op.opcode == 0xb4)
                       ? std::vector<uint16_t>{op12(op.opcode, 0, 1), 0x000f}
                       : op23(op.opcode, 0, 0, 1, 0x000f);
            checkInt(std::string(op.name) + " normal", spec, args,
                     rem ? 2 : 4);
            args[0].i = -22; args[1].i = 5;
            checkInt(std::string(op.name) + " negative", spec, args,
                     rem ? -2 : -4);
            args[0].i = INT32_MIN; args[1].i = -1;
            checkInt(std::string(op.name) + " MIN/-1", spec, args,
                     rem ? 0 : INT32_MIN);
            args[0].i = 7; args[1].i = 0;
            checkInt(std::string(op.name) + " zero", spec, args, 0, true);
        }
    }

    const IntOp longOps[] = {
        {"div-long", 0x9e, false, false},
        {"rem-long", 0x9f, false, false},
        {"div-long/2addr", 0xbe, false, false},
        {"rem-long/2addr", 0xbf, false, false},
    };
    for (const IntOp &op : longOps) {
        const bool rem = op.opcode == 0x9f || op.opcode == 0xbf;
        MethodSpec spec{"JJJ", "(JJ)J", {}, 4, 4};
        spec.insns = (op.opcode == 0xbe || op.opcode == 0xbf)
                   ? opWide12(op.opcode, 0, 2)
                   : opWide23(op.opcode, 0, 0, 2);
        jvalue args[2]{};
        args[0].j = 22; args[1].j = 5;
        checkLong(std::string(op.name) + " normal", spec, args,
                  rem ? 2 : 4);
        args[0].j = -22; args[1].j = 5;
        checkLong(std::string(op.name) + " negative", spec, args,
                  rem ? -2 : -4);
        args[0].j = INT64_MIN; args[1].j = -1;
        checkLong(std::string(op.name) + " MIN/-1", spec, args,
                  rem ? 0 : INT64_MIN);
        args[0].j = 7; args[1].j = 0;
        checkLong(std::string(op.name) + " zero", spec, args, 0, true);
    }
}

static uint16_t const4(int registerIndex, int literal) {
    return static_cast<uint16_t>(0x12 | (registerIndex << 8) |
                                 ((literal & 0xf) << 12));
}

static std::vector<uint16_t> branch22Body(uint8_t opcode) {
    /**
     * pc=0: conditional branch to pc=4; pc=2 is the not-taken path.
     * pc=3 goto jumps to the common return at pc=6.
     */
    return {
        static_cast<uint16_t>(opcode | (1 << 8) | (2 << 12)), 4,
        const4(0, 1),
        static_cast<uint16_t>(0x28 | (3 << 8)),
        const4(0, 2),
        0x0000,
        0x000f
    };
}

static std::vector<uint16_t> branch21Body(uint8_t opcode) {
    /** Same observable layout as branch22Body, with v1 compared to zero. */
    return {
        static_cast<uint16_t>(opcode | (1 << 8)), 4,
        const4(0, 1),
        static_cast<uint16_t>(0x28 | (3 << 8)),
        const4(0, 2),
        0x0000,
        0x000f
    };
}

static void appendU32Words(std::vector<uint16_t> &out, int32_t value) {
    const uint32_t bits = static_cast<uint32_t>(value);
    out.push_back(static_cast<uint16_t>(bits));
    out.push_back(static_cast<uint16_t>(bits >> 16));
}

static MethodSpec makeBranch22(uint8_t opcode) {
    return MethodSpec{"III", "(II)I", branch22Body(opcode), 3, 2};
}

static MethodSpec makeBranch21(uint8_t opcode) {
    return MethodSpec{"II", "(I)I", branch21Body(opcode), 2, 1};
}

static void testConditionalBranches() {
    struct Branch22 { const char *name; uint8_t opcode; int32_t takenA; int32_t takenB; int32_t notA; int32_t notB; };
    const Branch22 branches[] = {
        {"if-eq", 0x32, 7, 7, 7, 8},
        {"if-ne", 0x33, 7, 8, 7, 7},
        {"if-lt", 0x34, 1, 2, 2, 1},
        {"if-ge", 0x35, 2, 1, 1, 2},
        {"if-gt", 0x36, 2, 1, 1, 2},
        {"if-le", 0x37, 1, 2, 2, 1},
    };
    for (const Branch22 &branch : branches) {
        MethodSpec spec = makeBranch22(branch.opcode);
        jvalue args[2]{};
        args[0].i = branch.takenA; args[1].i = branch.takenB;
        checkInt(std::string(branch.name) + " taken", spec, args, 2);
        args[0].i = branch.notA; args[1].i = branch.notB;
        checkInt(std::string(branch.name) + " not taken", spec, args, 1);
    }

    struct Branch21 { const char *name; uint8_t opcode; int32_t taken; int32_t notTaken; };
    const Branch21 zeroBranches[] = {
        {"if-eqz", 0x38, 0, 1},
        {"if-nez", 0x39, 1, 0},
        {"if-ltz", 0x3a, -1, 1},
        {"if-gez", 0x3b, 1, -1},
        {"if-gtz", 0x3c, 1, -1},
        {"if-lez", 0x3d, -1, 1},
    };
    for (const Branch21 &branch : zeroBranches) {
        MethodSpec spec = makeBranch21(branch.opcode);
        jvalue arg{};
        arg.i = branch.taken;
        checkInt(std::string(branch.name) + " taken", spec, &arg, 2);
        arg.i = branch.notTaken;
        checkInt(std::string(branch.name) + " not taken", spec, &arg, 1);
    }
}

static void testGotos() {
    const std::vector<uint16_t> goto10 = {
        const4(0, 1),
        static_cast<uint16_t>(0x28 | (3 << 8)),
        const4(0, 2), 0x0000, 0x000f
    };
    const std::vector<uint16_t> goto16 = {
        const4(0, 1), 0x0029, 4,
        const4(0, 2), 0x0000, 0x000f
    };
    const std::vector<uint16_t> goto32 = {
        const4(0, 1), 0x002a, 5, 0,
        const4(0, 2), 0x0000, 0x000f
    };
    const MethodSpec specs[] = {
        {"I", "()I", goto10, 1, 0},
        {"I", "()I", goto16, 1, 0},
        {"I", "()I", goto32, 1, 0},
    };
    const char *names[] = {"goto", "goto/16", "goto/32"};
    for (int i = 0; i < 3; i++) {
        checkInt(std::string(names[i]) + " jumps", specs[i], nullptr, 1);
    }
}

static MethodSpec makePackedSwitch() {
    std::vector<uint16_t> code = {
        0x012b, 10, 0,                 // packed-switch v1, +10 -> pc10
        const4(0, -1),                 // default at pc3
        static_cast<uint16_t>(0x28 | (5 << 8)), // pc4 -> pc9
        const4(0, 1),                  // key 10 at pc5
        static_cast<uint16_t>(0x28 | (3 << 8)), // pc6 -> pc9
        const4(0, 2),                  // key 20 at pc7
        static_cast<uint16_t>(0x28 | (1 << 8)), // pc8 -> pc9
        0x000f,                        // common return at pc9
        0x0100, 11,                    // keys 10..20, payload at aligned pc10
    };
    appendU32Words(code, 10);          // first_key; packed keys are contiguous
    appendU32Words(code, 5);           // key 10 -> pc5 - pc0
    for (int key = 11; key < 20; key++)
        appendU32Words(code, 3);       // unused keys take the default path pc3
    appendU32Words(code, 7);           // key 20 -> pc7 - pc0
    return MethodSpec{"II", "(I)I", code, 2, 1};
}

static MethodSpec makeSparseSwitch() {
    std::vector<uint16_t> code = {
        0x012c, 12, 0,                 // sparse-switch v1, +12 -> pc12
        const4(0, -1),                 // default at pc3
        static_cast<uint16_t>(0x28 | (7 << 8)), // pc4 -> pc11
        const4(0, 1),                  // key -2 at pc5
        static_cast<uint16_t>(0x28 | (5 << 8)), // pc6 -> pc11
        const4(0, 2),                  // key 5 at pc7
        static_cast<uint16_t>(0x28 | (3 << 8)), // pc8 -> pc11
        const4(0, 3),                  // key 100 at pc9
        static_cast<uint16_t>(0x28 | (1 << 8)), // pc10 -> pc11
        0x000f,                        // common return at pc11
        0x0200, 3,                     // sparse-switch-payload, size=3
    };
    appendU32Words(code, -2);           // sorted keys
    appendU32Words(code, 5);
    appendU32Words(code, 100);
    appendU32Words(code, 5);            // target for -2: pc5 - pc0
    appendU32Words(code, 7);            // target for 5: pc7 - pc0
    appendU32Words(code, 9);            // target for 100: pc9 - pc0
    return MethodSpec{"II", "(I)I", code, 2, 1};
}

static void testSwitches() {
    MethodSpec packed = makePackedSwitch();
    jvalue packedArg{};
    packedArg.i = 10;
    checkInt("packed-switch case 10", packed, &packedArg, 1);
    packedArg.i = 20;
    checkInt("packed-switch case 20", packed, &packedArg, 2);
    packedArg.i = 99;
    checkInt("packed-switch default", packed, &packedArg, -1);

    MethodSpec sparse = makeSparseSwitch();
    jvalue sparseArg{};
    sparseArg.i = -2;
    checkInt("sparse-switch case -2", sparse, &sparseArg, 1);
    sparseArg.i = 5;
    checkInt("sparse-switch case 5", sparse, &sparseArg, 2);
    sparseArg.i = 100;
    checkInt("sparse-switch case 100", sparse, &sparseArg, 3);
    sparseArg.i = 7;
    checkInt("sparse-switch default", sparse, &sparseArg, -1);
}

static void testArrayOpcodes() {
    const std::vector<std::string> creationTypes = {
        "[B", "[C", "[I", "[J", "[Ljava/lang/Object;"
    };
    for (const std::string &descriptor : creationTypes) {
        MethodSpec spec = makeNewArray(descriptor);
        jvalue length{};
        length.i = 3;
        checkArrayCreation("new-array " + descriptor, spec, &length, 3, descriptor);
    }

    checkIntArrayContents("filled-new-array", makeFilledNewArray(false),
                         {1, 2, 3});
    checkIntArrayContents("filled-new-array/range", makeFilledNewArray(true),
                         {1, 2, 3});
    checkIntArrayContents("filled-new-array/range", makeFilledNewArray(true),
                         {1, 2, 3});

    jvalue floatArgs[3]{};
    floatArgs[0].f = 1.5f;
    floatArgs[1].f = 2.25f;
    floatArgs[2].f = -3.5f;
    checkFloatApprox("aget/aput-float", makeFloatArrayRoundTrip(), floatArgs, 2.25f);

    jvalue doubleArgs[3]{};
    doubleArgs[0].d = 1.5;
    doubleArgs[1].d = 2.25;
    doubleArgs[2].d = -3.5;
    checkDoubleApprox("aget/aput-double", makeDoubleArrayRoundTrip(), doubleArgs, 2.25);

    checkFilledArray("fill-array-data byte", makeFillArrayData(
            "[B", 1, 3, {0xfe01, 0x007f}), "[B", {1, -2, 127});
    checkFilledArray("fill-array-data short", makeFillArrayData(
            "[S", 2, 3, {0xfed4, 0xfff9, 0x0929}), "[S", {-300, -7, 2345});
    checkFilledArray("fill-array-data char", makeFillArrayData(
            "[C", 2, 3, {0x1234, 0x2345, 0x3456}), "[C", {0x1234, 0x2345, 0x3456});
    checkFilledArray("fill-array-data int", makeFillArrayData(
            "[I", 4, 3, {0x0001, 0x0000, 0xfffe, 0xffff,
                         0xdef0, 0x9abc}),
            "[I", {1, -2, static_cast<int64_t>(static_cast<int32_t>(0x9abcdef0U))});
    checkFilledArray("fill-array-data long", makeFillArrayData(
            "[J", 8, 2, {0x7788, 0x5566, 0x3344, 0x1122,
                         0xff00, 0xddee, 0xbbcc, 0x99aa}),
            "[J", {static_cast<int64_t>(0x1122334455667788ULL),
                    static_cast<int64_t>(0x99aabbccddeeff00ULL)});

    MethodSpec lengthSpec = makeArrayLength("[I");
    jvalue lengthArg{};
    lengthArg.i = 3;
    checkInt("array-length non-empty", lengthSpec, &lengthArg, 3);
    lengthArg.i = 0;
    checkInt("array-length zero", lengthSpec, &lengthArg, 0);

    MethodSpec nullLength = makeNullArrayLength();
    jvalue nullArray{};
    checkException("array-length null", nullLength, &nullArray, true, false);

    struct NarrowArray {
        const char *name;
        const char *descriptor;
        uint8_t aput;
        uint8_t aget;
        int16_t values[3];
    };
    const NarrowArray narrow[] = {
        {"int", "[I", 0x4b, 0x44, {111, 222, 333}},
        {"boolean", "[Z", 0x4e, 0x47, {0, 1, 1}},
        {"byte", "[B", 0x4f, 0x48, {-123, -7, 120}},
        {"char", "[C", 0x50, 0x49, {0x1234, 0x2345, 0x3456}},
        {"short", "[S", 0x51, 0x4a, {-1234, -7, 2345}},
    };
    for (const NarrowArray &array : narrow) {
        for (int index = 0; index < 3; index++) {
            MethodSpec spec = makeNarrowArrayRoundTrip(
                    array.descriptor, array.aput, array.aget,
                    array.values, index);
            checkInt(std::string("aget/aput-") + array.name + " index " +
                             std::to_string(index),
                     spec, nullptr, array.values[index]);
        }
    }

    const int64_t wideValues[3] = {
        static_cast<int64_t>(0x1122334455667788ULL),
        static_cast<int64_t>(0x99aabbccddeeff00ULL),
        static_cast<int64_t>(0x0123456789abcdefULL),
    };
    MethodSpec wideSpec = makeLongArrayRoundTrip(0);
    jvalue wideArgs[3]{};
    for (int i = 0; i < 3; i++) wideArgs[i].j = wideValues[i];
    for (int index = 0; index < 3; index++) {
        wideSpec = makeLongArrayRoundTrip(index);
        checkLong("aget/aput-wide index " + std::to_string(index),
                  wideSpec, wideArgs, wideValues[index]);
    }

    MethodSpec objectSpec;
    for (int index = 0; index < 3; index++) {
        objectSpec = makeObjectArrayRoundTrip(index);
        checkObjectRoundTrip("aget/aput-object index " + std::to_string(index),
                             objectSpec, nullptr);
    }

    MethodSpec intBounds = makeIntBoundsTest();
    jvalue index{};
    index.i = -1;
    checkException("aget int index -1", intBounds, &index, false, true);
    index.i = 1;
    checkException("aget int index length", intBounds, &index, false, true);

    MethodSpec longBounds = makeLongBoundsTest();
    index.i = -1;
    checkException("aget-wide index -1", longBounds, &index, false, true);
    index.i = 1;
    checkException("aget-wide index length", longBounds, &index, false, true);

    MethodSpec objectBounds = makeObjectBoundsTest();
    index.i = -1;
    checkException("aget-object index -1", objectBounds, &index, false, true);
    index.i = 1;
    checkException("aget-object index length", objectBounds, &index, false, true);

    MethodSpec nullGet = makeNullAget();
    jvalue nullGetArgs[2]{};
    nullGetArgs[0].l = nullptr;
    nullGetArgs[1].i = 0;
    checkException("aget null array", nullGet, nullGetArgs, true, false);

    MethodSpec nullPut = makeNullAput();
    jvalue nullPutArgs[2]{};
    nullPutArgs[0].l = nullptr;
    nullPutArgs[1].i = 123;
    checkException("aput null array", nullPut, nullPutArgs, true, false);
}

static void testFieldOpcodes() {
    if (!ensureFieldFixture()) {
        fail("field fixture setup", "DefineClass(HostFields) failed");
        return;
    }

    jobject holder = newFieldFixtureObject();
    if (!holder) {
        fail("field fixture object", "HostFields constructor failed");
        return;
    }

    MethodSpec instanceInt = makeInstanceIntField();
    jvalue instanceIntArgs[1]{};
    instanceIntArgs[0].l = holder;
    checkInt("iget/iput int", instanceInt, instanceIntArgs, 123);

    MethodSpec instanceWide = makeInstanceWideField();
    jvalue instanceWideArgs[1]{};
    instanceWideArgs[0].l = holder;
    checkLong("iget/iput-wide long", instanceWide, instanceWideArgs,
              static_cast<int64_t>(0x1122334455667788ULL));

    jstring objectValue = g_env->NewStringUTF("field-object-value");
    MethodSpec instanceObject = makeInstanceObjectField();
    jvalue instanceObjectArgs[2]{};
    instanceObjectArgs[0].l = holder;
    instanceObjectArgs[1].l = objectValue;
    checkReturnedObjectIdentity("iget/iput-object", instanceObject,
                               instanceObjectArgs, objectValue);

    jvalue nullHolder[1]{};
    checkException("iget/iput null receiver", instanceInt, nullHolder, true, false);

    MethodSpec staticInt = makeStaticIntField();
    jvalue staticIntArgs[1]{};
    staticIntArgs[0].i = 314159;
    checkInt("sget/sput int", staticInt, staticIntArgs, 314159);

    MethodSpec staticWide = makeStaticWideField();
    jvalue staticWideArgs[1]{};
    staticWideArgs[0].j = static_cast<int64_t>(0x8877665544332211ULL);
    checkLong("sget/sput-wide long", staticWide, staticWideArgs,
              static_cast<int64_t>(0x8877665544332211ULL));

    MethodSpec staticObject = makeStaticObjectField();
    jvalue staticObjectArgs[1]{};
    staticObjectArgs[0].l = objectValue;
    checkReturnedObjectIdentity("sget/sput-object", staticObject,
                               staticObjectArgs, objectValue);

    struct NarrowFieldCase {
        const char *name;
        const char *descriptor;
        const char *instanceName;
        const char *staticName;
        uint8_t instancePut;
        uint8_t instanceGet;
        uint8_t staticPut;
        uint8_t staticGet;
        jint value;
    };
    const NarrowFieldCase narrow[] = {
        {"boolean", "Z", "z", "sz", 0x5c, 0x55, 0x6a, 0x63, 1},
        {"byte", "B", "b", "sb", 0x5d, 0x56, 0x6b, 0x64, -123},
        {"char", "C", "c", "sc", 0x5e, 0x57, 0x6c, 0x65, 0x1234},
        {"short", "S", "s", "ss", 0x5f, 0x58, 0x6d, 0x66, -1234},
    };
    for (const NarrowFieldCase &field : narrow) {
        MethodSpec instance = makeInstanceNarrowField(
                field.descriptor, field.instanceName,
                field.instancePut, field.instanceGet);
        jvalue instanceArgs[2]{};
        instanceArgs[0].l = holder;
        instanceArgs[1].i = field.value;
        checkInt(std::string("iget/iput-") + field.name,
                 instance, instanceArgs, field.value);

        MethodSpec statik = makeStaticNarrowField(
                field.descriptor, field.staticName,
                field.staticPut, field.staticGet);
        jvalue staticArgs[1]{};
        staticArgs[0].i = field.value;
        checkInt(std::string("sget/sput-") + field.name,
                 statik, staticArgs, field.value);
    }

    if (objectValue) g_env->DeleteLocalRef(objectValue);
    g_env->DeleteLocalRef(holder);
}

static void testExceptionOpcodes() {
    checkException("uncaught throw null", makeUncaughtThrowNull(), nullptr,
                   true, false);

    jvalue nullArray{};
    checkReturnedObjectClass("caught array-length NullPointerException",
                             makeCatchNullArrayLength(), &nullArray,
                             "java/lang/NullPointerException");

    jobject exception = makeRuntimeExceptionObject();
    if (!exception) {
        fail("caught throw fixture setup", "RuntimeException creation failed");
        if (g_env->ExceptionCheck()) g_env->ExceptionClear();
        return;
    }
    jvalue exceptionArg{};
    exceptionArg.l = exception;
    checkReturnedObjectIdentity("caught throw object", makeCaughtThrowObject(),
                               &exceptionArg, exception);
    g_env->DeleteLocalRef(exception);
}

static void testReturnOpcodes() {
    checkVoid("return-void stops", makeReturnVoidStops(), nullptr);
    checkInt("return stops", makeReturnIntStops(), nullptr, 42);
    checkLong("return-wide stops", makeReturnWideStops(), nullptr,
              static_cast<int64_t>(0x1122334455667788ULL));

    jobject object = makeIntegerObject(7);
    if (!object) {
        fail("return-object fixture setup", "Integer object creation failed");
        if (g_env->ExceptionCheck()) g_env->ExceptionClear();
        return;
    }
    jvalue objectArg{};
    objectArg.l = object;
    checkReturnedObjectIdentity("return-object stops", makeReturnObjectStops(),
                               &objectArg, object);
    g_env->DeleteLocalRef(object);
}

static void testInvocationOpcodes() {
    jobject intObject = promoteTestReference(makeIntegerObject(37));
    jobject longObject = promoteTestReference(
            makeLongObject(static_cast<jlong>(0x1122334455667788ULL)));
    jobject listObject = promoteTestReference(makeListObject(3));
    jstring hello = static_cast<jstring>(promoteTestReference(
            g_env->NewStringUTF("hello")));
    jclass integerClass = static_cast<jclass>(promoteTestReference(
            g_env->FindClass("java/lang/Integer")));

    if (!intObject || !longObject || !listObject || !hello || !integerClass) {
        fail("invoke fixture setup", "host invocation object creation failed");
        releaseTestGlobal(intObject);
        releaseTestGlobal(longObject);
        releaseTestGlobal(listObject);
        releaseTestGlobal(hello);
        releaseTestGlobal(integerClass);
        if (g_env->ExceptionCheck()) g_env->ExceptionClear();
        return;
    }

    jvalue integerArg[1]{};
    integerArg[0].l = intObject;
    checkInt("invoke-virtual int", makeInvokeVirtualInt(), integerArg, 37);
    checkInt("invoke-virtual/range int", makeInvokeVirtualInt(true), integerArg, 37);
    checkInt("invoke-direct int", makeInvokeDirectInt(), integerArg, 37);
    checkInt("invoke-direct/range int", makeInvokeDirectInt(true), integerArg, 37);

    checkReturnedObjectIdentity("invoke-super object", makeInvokeSuperClass(),
                               integerArg, integerClass);
    checkReturnedObjectIdentity("invoke-super/range object",
                               makeInvokeSuperClass(true), integerArg, integerClass);

    jvalue longArg[1]{};
    longArg[0].l = longObject;
    checkLong("invoke-virtual wide return", makeInvokeVirtualWide(), longArg,
              static_cast<int64_t>(0x1122334455667788ULL));

    checkStringResult("invoke-virtual object return", makeInvokeVirtualObject(),
                      integerArg, "37");
    checkStringResult("invoke-virtual object return", makeInvokeVirtualObject(),
                      integerArg, "37");

    checkStringResult("move-result-object destination register",
                      makeInvokeVirtualObject(1), integerArg, "37");

    jvalue substringArgs[3]{};
    substringArgs[0].l = hello;
    substringArgs[1].i = 1;
    substringArgs[2].i = 4;
    checkStringResult("invoke-virtual arguments", makeInvokeVirtualArguments(),
                      substringArgs, "ell");

    jvalue maxArgs[2]{};
    maxArgs[0].i = 17;
    maxArgs[1].i = 42;
    checkInt("invoke-static int", makeInvokeStaticInt(), maxArgs, 42);
    checkInt("invoke-static/range int", makeInvokeStaticInt(true), maxArgs, 42);
    checkInt("invoke-static void continuation", makeInvokeStaticVoid(), nullptr, 7);
    checkInt("invoke-static/range void continuation",
              makeInvokeStaticVoid(true), nullptr, 7);
    checkInt("invoke-static/range void continuation",
              makeInvokeStaticVoid(true), nullptr, 7);
    checkInt("move-result destination register",
             makeInvokeStaticInt(false, 2), maxArgs, 42);

    jvalue wideArgs[2]{};
    wideArgs[0].j = static_cast<jlong>(0x100000000LL);
    wideArgs[1].j = 7;
    checkLong("invoke-static wide arguments", makeInvokeStaticWide(), wideArgs,
              static_cast<int64_t>(0x100000007LL));
    checkLong("invoke-static/range wide arguments",
              makeInvokeStaticWide(true), wideArgs,
              static_cast<int64_t>(0x100000007LL));
    checkLong("invoke-static/range wide arguments",
              makeInvokeStaticWide(true), wideArgs,
              static_cast<int64_t>(0x100000007LL));
    checkLong("move-result-wide destination registers",
              makeInvokeStaticWide(false, 4), wideArgs,
              static_cast<int64_t>(0x100000007LL));

    jvalue listArg[1]{};
    listArg[0].l = listObject;
    checkInt("invoke-interface int", makeInvokeInterfaceInt(), listArg, 3);
    checkInt("invoke-interface/range int", makeInvokeInterfaceInt(true), listArg, 3);

    jvalue listIndexArgs[2]{};
    listIndexArgs[0].l = listObject;
    listIndexArgs[1].l = intObject;
    checkInt("invoke-interface object argument", makeInvokeInterfaceIndexOf(),
             listIndexArgs, -1);
    checkInt("invoke-interface/range object argument",
             makeInvokeInterfaceIndexOf(true), listIndexArgs, -1);

    checkInt("nested invoke-static return", makeNestedStaticInvoke(), maxArgs, 91);

    jvalue nullReceiver[1]{};
    checkException("invoke-virtual null receiver", makeInvokeVirtualInt(),
                   nullReceiver, true, false);

    releaseTestGlobal(intObject);
    releaseTestGlobal(longObject);
    releaseTestGlobal(listObject);
    releaseTestGlobal(hello);
    releaseTestGlobal(integerClass);
}

static void testFloatingConversions() {
    const float floatValues[] = {
        0.0f, -0.0f, 3.75f, -3.75f,
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity(),
        -std::numeric_limits<float>::infinity(),
        0x1p31f, -0x1p31f,
        std::nextafterf(0x1p31f, 0.0f),
        std::nextafterf(-0x1p31f, -std::numeric_limits<float>::infinity()),
        0x1p63f, -0x1p63f,
        std::nextafterf(0x1p63f, 0.0f),
        std::nextafterf(-0x1p63f, -std::numeric_limits<float>::infinity()),
    };
    const double doubleValues[] = {
        0.0, -0.0, 3.75, -3.75,
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(),
        2147483647.0, 2147483648.0, -2147483648.0,
        0x1p63, -0x1p63,
        std::nextafter(0x1p63, 0.0),
        std::nextafter(-0x1p63, -std::numeric_limits<double>::infinity()),
    };

    MethodSpec ftoi{"IF", "(F)I", {op12(0x87, 0, 1), 0x000f}, 2, 1};
    MethodSpec ftol{"JF", "(F)J", {op12(0x88, 0, 1), 0x0010}, 2, 1};
    MethodSpec dtoi{"ID", "(D)I", {op12(0x8a, 0, 0), 0x000f}, 2, 2};
    MethodSpec dtol{"JD", "(D)J", {op12(0x8b, 0, 0), 0x0010}, 2, 2};

    for (float value : floatValues) {
        jvalue arg{}; arg.f = value;
        const int32_t expectedInt = std::isnan(value) ? 0 :
            value >= 0x1p31f ? INT32_MAX :
            value <= -0x1p31f ? INT32_MIN : static_cast<int32_t>(value);
        const int64_t expectedLong = std::isnan(value) ? 0 :
            value >= 0x1p63f ? INT64_MAX :
            value <= -0x1p63f ? INT64_MIN : static_cast<int64_t>(value);
        checkFpInt("float-to-int edge", ftoi, &arg, expectedInt);
        checkFpLong("float-to-long edge", ftol, &arg, expectedLong);
    }

    for (double value : doubleValues) {
        jvalue arg{}; arg.d = value;
        const int32_t expectedInt = std::isnan(value) ? 0 :
            value >= 0x1p31 ? INT32_MAX :
            value <= -0x1p31 ? INT32_MIN : static_cast<int32_t>(value);
        const int64_t expectedLong = std::isnan(value) ? 0 :
            value >= 0x1p63 ? INT64_MAX :
            value <= -0x1p63 ? INT64_MIN : static_cast<int64_t>(value);
        checkFpInt("double-to-int edge", dtoi, &arg, expectedInt);
        checkFpLong("double-to-long edge", dtol, &arg, expectedLong);
    }
}

static bool startJvm() {
    JavaVMInitArgs args{};
    args.version = JNI_VERSION_1_8;
    args.ignoreUnrecognized = JNI_TRUE;
    void *env = nullptr;
    return JNI_CreateJavaVM(&g_vm, &env, &args) == JNI_OK &&
           (g_env = static_cast<JNIEnv *>(env)) != nullptr;
}

} // namespace

int main() {
    if (!startJvm()) {
        fprintf(stderr, "Unable to create the host JVM\n");
        return 2;
    }

    testMoveConstOpcodes();
    testCompareOpcodes();
    testFloatBinaryOpcodes();
    testDoubleBinaryOpcodes();
    testIntBinaryOpcodes();
    testLongBinaryOpcodes();
    testIntLiteralOpcodes();
    testIntegerOpcodes();
    testTwoAddrOpcodes();
    testConditionalBranches();
    testGotos();
    testSwitches();
    testArrayOpcodes();
    testFieldOpcodes();
    testExceptionOpcodes();
    testReturnOpcodes();
    testInvocationOpcodes();
    testFloatingConversions();

    printf("\nVMP Opcode Tests\n================\n\nPassed:  %d\nFailed:  %d\nSkipped: %d\nTotal:   %d\n",
           passed, failed, skipped, passed + failed + skipped);

    g_vm->DestroyJavaVM();
    return failed == 0 ? 0 : 1;
}
