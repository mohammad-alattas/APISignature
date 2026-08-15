// Asserts the C++ normalizer against the same contract the Python one uses.
//
// The fixture table is generated from etl/tests/normalize_cases.json by
// etl/gen_cpp_fixtures.py. If the two implementations drift, this fails -- which
// matters because a disagreement between them means the index is built with one
// set of keys and searched with another, and the panel silently goes blank for
// the APIs that matter most.

#include <cstdio>
#include <string>
#include <vector>

#include "normalize.h"

namespace {

struct NormalizeCase {
    const char* raw;
    const char* function;
    const char* module;
    int ordinal;
    bool is_apiset;
    std::vector<std::string> keys;
    const char* canonical;
};

#include "normalize_cases.inc"

int g_failures = 0;

void fail(const std::string& label, const std::string& expected,
          const std::string& actual) {
    std::printf("  FAIL %s\n       expected: %s\n       actual:   %s\n",
                label.c_str(), expected.c_str(), actual.c_str());
    ++g_failures;
}

std::string join(const std::vector<std::string>& values) {
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) {
            out += ", ";
        }
        out += values[i];
    }
    return out + "]";
}

void expect_eq(const std::string& label, const std::string& expected,
               const std::string& actual) {
    if (expected != actual) {
        fail(label, "\"" + expected + "\"", "\"" + actual + "\"");
    }
}

void check_contract() {
    std::printf("shared contract (%zu cases)\n",
                sizeof(kNormalizeCases) / sizeof(kNormalizeCases[0]));

    for (const NormalizeCase& c : kNormalizeCases) {
        const malapi::Symbol symbol = malapi::parse_symbol(c.raw);
        const std::string label = std::string("parse_symbol(\"") + c.raw + "\")";

        expect_eq(label + ".function", c.function, symbol.function);
        expect_eq(label + ".module", c.module, symbol.module);

        if (symbol.ordinal != c.ordinal) {
            fail(label + ".ordinal", std::to_string(c.ordinal),
                 std::to_string(symbol.ordinal));
        }
        if (symbol.is_apiset != c.is_apiset) {
            fail(label + ".is_apiset", c.is_apiset ? "true" : "false",
                 symbol.is_apiset ? "true" : "false");
        }
        if (symbol.lookup_keys != c.keys) {
            fail(label + ".lookup_keys", join(c.keys), join(symbol.lookup_keys));
        }
        expect_eq(label + ".canonical_key", c.canonical, symbol.canonical_key);
    }
}

void check_unit_behaviour() {
    std::printf("unit behaviour\n");

    expect_eq("strip __imp_", "CreateProcessW",
              malapi::strip_decoration("__imp_CreateProcessW"));
    expect_eq("strip stdcall", "VirtualAllocEx",
              malapi::strip_decoration("_VirtualAllocEx@20"));

    expect_eq("fold W", "CreateProcess",
              malapi::fold_charset_suffix("CreateProcessW"));
    expect_eq("fold A", "CreateProcess",
              malapi::fold_charset_suffix("CreateProcessA"));
    expect_eq("fold underscore variant", "DnsQuery",
              malapi::fold_charset_suffix("DnsQuery_A"));
    expect_eq("all-caps acronym is left alone", "RSA",
              malapi::fold_charset_suffix("RSA"));

    // MalAPI title-cases the Winsock family; the real exports are lowercase.
    expect_eq("Winsock case folds", malapi::canonical("socket"),
              malapi::canonical("Socket"));
    expect_eq("MalAPI vs Microsoft casing", malapi::canonical("GetKeyNameTextA"),
              malapi::canonical("GetKeynameTextA"));

    // VirtualAlloc and VirtualAllocEx are different functions.
    if (malapi::canonical("VirtualAlloc") == malapi::canonical("VirtualAllocEx")) {
        fail("Ex suffix must not collapse", "different", "same");
    }

    expect_eq("Zw folds to Nt", "NtOpenProcess",
              malapi::fold_zw_to_nt("ZwOpenProcess"));

    if (!malapi::is_native_api("RtlMoveMemory")) {
        fail("is_native_api(RtlMoveMemory)", "true", "false");
    }
    if (malapi::is_native_api("CreateProcessW")) {
        fail("is_native_api(CreateProcessW)", "false", "true");
    }
}

}  // namespace

int main() {
    check_contract();
    check_unit_behaviour();

    if (g_failures) {
        std::printf("\n%d assertion(s) failed\n", g_failures);
        return 1;
    }
    std::printf("\nall assertions passed\n");
    return 0;
}
