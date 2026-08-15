// Evaluator for capa feature programs.
//
// Mirror of `evaluate` in etl/sources/capa.py. The ETL flattens each capa rule's
// boolean tree into a postfix opcode stream, so the runtime needs no YAML parser
// and no tree walk -- a match is a pass over a few dozen bytes.
//
// Features capa tests that an import table cannot answer -- strings, constants,
// byte patterns -- compile to OP_UNKNOWN. What the caller does with those is the
// single most consequential decision in the whole tool: treating them as true
// reports 152 capabilities for notepad.exe, including "bypass UAC".

#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_set>

namespace malapi {

// Byte-for-byte the same as etl/sources/capa.py.
enum CapaOp : uint8_t {
    kOpApi     = 0x01,  // + u32 api_id    push: api_id is in the target's set
    kOpUnknown = 0x02,  //                 push: a feature we cannot evaluate
    kOpTrue    = 0x03,  //                 push: always satisfied (`optional:`)
    kOpFalse   = 0x04,  //                 push: statically unsatisfiable here
    kOpAnd     = 0x10,  // + u16 count     pop count, push their conjunction
    kOpOr      = 0x11,  // + u16 count     pop count, push their disjunction
    kOpNot     = 0x12,  //                 pop 1, push its negation
    kOpNOf     = 0x13,  // + u16 n, u16 c  pop c, push (at least n are true)
};

// Evaluate a program against the API ids present in the target.
//
// Returns false rather than throwing on a malformed program. This runs inside a
// debugger callback, so a corrupt index must degrade to "no capabilities" rather
// than take x64dbg down mid-analysis. The ETL validates every program at build
// time, so a failure here means the file was truncated or tampered with.
bool capa_evaluate(const uint8_t* program, size_t size,
                   const std::unordered_set<uint32_t>& present,
                   bool unknown_is_true);

}  // namespace malapi
