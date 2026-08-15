#include "capa_eval.h"

#include <cstring>
#include <vector>

namespace malapi {
namespace {

// capa's deepest rules nest a handful of levels; this is generous. The cap
// exists so a malformed program cannot make us allocate without bound.
constexpr size_t kMaxStack = 256;

bool read_u16(const uint8_t* program, size_t size, size_t& offset, uint16_t& out) {
    if (offset + 2 > size) {
        return false;
    }
    std::memcpy(&out, program + offset, 2);  // little-endian, as the ETL emits
    offset += 2;
    return true;
}

bool read_u32(const uint8_t* program, size_t size, size_t& offset, uint32_t& out) {
    if (offset + 4 > size) {
        return false;
    }
    std::memcpy(&out, program + offset, 4);
    offset += 4;
    return true;
}

}  // namespace

bool capa_evaluate(const uint8_t* program, size_t size,
                   const std::unordered_set<uint32_t>& present,
                   bool unknown_is_true) {
    if (!program || size == 0) {
        return false;
    }

    std::vector<bool> stack;
    stack.reserve(16);

    size_t offset = 0;
    while (offset < size) {
        const uint8_t op = program[offset++];

        switch (op) {
            case kOpApi: {
                uint32_t api_id = 0;
                if (!read_u32(program, size, offset, api_id)) {
                    return false;
                }
                stack.push_back(present.find(api_id) != present.end());
                break;
            }
            case kOpUnknown:
                stack.push_back(unknown_is_true);
                break;
            case kOpTrue:
                stack.push_back(true);
                break;
            case kOpFalse:
                stack.push_back(false);
                break;
            case kOpNot: {
                if (stack.empty()) {
                    return false;
                }
                const bool value = stack.back();
                stack.back() = !value;
                break;
            }
            case kOpAnd:
            case kOpOr: {
                uint16_t count = 0;
                if (!read_u16(program, size, offset, count) || stack.size() < count) {
                    return false;
                }
                // AND is the conjunction of its operands, OR the disjunction.
                // An empty AND is true and an empty OR false, matching Python's
                // all()/any() -- the ETL does not emit those, but agreeing with
                // the reference implementation on edge cases is the point.
                bool result = (op == kOpAnd);
                for (uint16_t i = 0; i < count; ++i) {
                    const bool operand = stack.back();
                    stack.pop_back();
                    result = (op == kOpAnd) ? (result && operand) : (result || operand);
                }
                stack.push_back(result);
                break;
            }
            case kOpNOf: {
                uint16_t threshold = 0;
                uint16_t count = 0;
                if (!read_u16(program, size, offset, threshold) ||
                    !read_u16(program, size, offset, count) || stack.size() < count) {
                    return false;
                }
                uint16_t satisfied = 0;
                for (uint16_t i = 0; i < count; ++i) {
                    satisfied += stack.back() ? 1 : 0;
                    stack.pop_back();
                }
                stack.push_back(satisfied >= threshold);
                break;
            }
            default:
                return false;  // unknown opcode: corrupt or newer than this build
        }

        if (stack.size() > kMaxStack) {
            return false;
        }
    }

    // A well-formed program leaves exactly one value. Anything else means the
    // stream was truncated or the emitter and this evaluator disagree.
    return stack.size() == 1 && stack.front();
}

}  // namespace malapi
