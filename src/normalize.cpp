#include "normalize.h"

#include <algorithm>
#include <array>
#include <cctype>

namespace malapi {
namespace {

bool is_lower(char c) {
    return c >= 'a' && c <= 'z';
}

bool is_upper(char c) {
    return c >= 'A' && c <= 'Z';
}

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

bool is_ident_char(char c) {
    return is_lower(c) || is_upper(c) || is_digit(c) || c == '_';
}

bool is_identifier(const std::string& text) {
    if (text.empty()) {
        return false;
    }
    if (is_digit(text.front())) {
        return false;
    }
    return std::all_of(text.begin(), text.end(), is_ident_char);
}

std::string to_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::string trim(const std::string& text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

// Strip any mix of leading/trailing angle brackets and ampersands, which is how
// x64dbg wraps import references: <&kernel32.VirtualAllocEx>
std::string strip_wrappers(std::string text) {
    text = trim(text);
    while (!text.empty() && (text.front() == '<' || text.front() == '&')) {
        text.erase(text.begin());
    }
    while (!text.empty() && (text.back() == '>' || text.back() == '&')) {
        text.pop_back();
    }
    return trim(text);
}

bool starts_with(const std::string& text, const std::string& prefix) {
    return text.size() >= prefix.size() &&
           text.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Native API prefixes. These take UNICODE_STRING and have no ANSI or Unicode
// spellings, so expanding A/W siblings for them produces keys that never hit.
constexpr std::array<const char*, 7> kNativePrefixes = {
    "Nt", "Zw", "Rtl", "Ldr", "Ke", "Csr", "Dbg"};

// Modules that forward to, or are implementation details of, another module.
// Advisory only -- module never filters a lookup, because apiset and forwarder
// chains make a strict DLL match wrong more often than right.
struct ModuleAlias {
    const char* from;
    const char* to;
};

constexpr std::array<ModuleAlias, 4> kModuleAliases = {{
    {"kernelbase", "kernel32"},
    {"ntoskrnl", "ntdll"},
    {"wow64win", "win32u"},
    {"sechost", "advapi32"},
}};

void push_unique(std::vector<std::string>& keys, const std::string& key) {
    if (key.empty()) {
        return;
    }
    if (std::find(keys.begin(), keys.end(), key) == keys.end()) {
        keys.push_back(key);
    }
}

// Ordered exact-spelling candidates, most specific first.
//
// Matched against api.name, so they keep their original case; the case-folded
// fallback is Symbol::canonical_key and is tried only after these all miss.
//
// The exact spelling comes first so CreateProcessA lands on the ANSI entry
// directly rather than arriving through the base name. Charset siblings expand
// in both directions: W->A reaches MalAPI's 122 ANSI-only entries from the
// spelling seen at runtime, and bare->A/W lets a capa rule written as
// `api: CreateProcess` match a row stored as CreateProcessA.
std::vector<std::string> build_lookup_keys(const std::string& function) {
    std::vector<std::string> keys;
    const std::string base = fold_charset_suffix(function);

    push_unique(keys, function);
    push_unique(keys, fold_zw_to_nt(function));
    push_unique(keys, base);

    if (!is_native_api(function)) {
        push_unique(keys, base + "A");
        push_unique(keys, base + "W");
    }
    return keys;
}

}  // namespace

std::string strip_decoration(const std::string& raw) {
    std::string name = trim(raw);

    static const std::array<const char*, 4> kPrefixes = {
        "__imp__", "__imp_", "_imp__", "_imp_"};
    for (const char* prefix : kPrefixes) {
        if (starts_with(name, prefix)) {
            name.erase(0, std::string(prefix).size());
            break;
        }
    }

    // 32-bit stdcall decoration: _VirtualAllocEx@20
    if (name.size() > 2 && name.front() == '_') {
        const auto at = name.rfind('@');
        if (at != std::string::npos && at + 1 < name.size()) {
            const bool all_digits = std::all_of(
                name.begin() + static_cast<long>(at) + 1, name.end(), is_digit);
            const std::string inner = name.substr(1, at - 1);
            if (all_digits && is_identifier(inner)) {
                name = inner;
            }
        }
    }
    return name;
}

std::string fold_charset_suffix(const std::string& name) {
    if (name.size() < 2) {
        return name;
    }
    const char last = name.back();
    if (last != 'A' && last != 'W') {
        return name;
    }

    const char preceding = name[name.size() - 2];
    if (is_lower(preceding) || is_digit(preceding)) {
        return name.substr(0, name.size() - 1);
    }
    // DnsQuery_A -> DnsQuery, so both spellings share one canonical key.
    if (preceding == '_' && name.size() > 2) {
        return name.substr(0, name.size() - 2);
    }
    return name;
}

std::string fold_zw_to_nt(const std::string& name) {
    if (name.size() > 2 && name[0] == 'Z' && name[1] == 'w' && is_upper(name[2])) {
        return "Nt" + name.substr(2);
    }
    return name;
}

std::string canonical(const std::string& name) {
    // Case-folded last, and deliberately. MalAPI title-cases the Winsock family
    // -- Socket, Accept, Recv, Listen, Closesocket -- while the real exports and
    // Microsoft's pages are lowercase, and it writes GetKeynameTextA where
    // Microsoft has GetKeyNameTextA. A case-sensitive key leaves the intent
    // layer unreachable for all of them. Folding runs first because the A/W and
    // Zw rules need the original case to tell a charset suffix from an acronym.
    return to_lower(fold_zw_to_nt(fold_charset_suffix(strip_decoration(name))));
}

bool is_native_api(const std::string& function) {
    for (const char* prefix : kNativePrefixes) {
        const std::string p(prefix);
        if (function.size() > p.size() && starts_with(function, p) &&
            is_upper(function[p.size()])) {
            return true;
        }
    }
    return false;
}

void normalize_module(const std::string& raw, std::string& out, bool& is_apiset) {
    out.clear();
    is_apiset = false;

    std::string module = to_lower(strip_wrappers(raw));
    if (module.empty()) {
        return;
    }

    static const std::array<const char*, 5> kSuffixes = {
        ".dll", ".exe", ".sys", ".drv", ".lib"};
    for (const char* suffix : kSuffixes) {
        if (ends_with(module, suffix)) {
            module.erase(module.size() - std::string(suffix).size());
            break;
        }
    }

    if (starts_with(module, "api-ms-win-") || starts_with(module, "ext-ms-win-")) {
        is_apiset = true;
        return;
    }
    if (module.empty()) {
        return;
    }

    for (const ModuleAlias& alias : kModuleAliases) {
        if (module == alias.from) {
            out = alias.to;
            return;
        }
    }
    out = module;
}

Symbol parse_symbol(const std::string& raw) {
    Symbol symbol;
    symbol.raw = raw;

    std::string text = trim(raw);
    if (text.empty()) {
        return symbol;
    }

    // Pull the symbol out of a memory operand: ds:[<&CreateProcessW>]
    const auto open = text.find('[');
    if (open != std::string::npos) {
        const auto close = text.find(']', open + 1);
        if (close != std::string::npos) {
            text = text.substr(open + 1, close - open - 1);
        }
    }

    text = strip_wrappers(text);

    // x64dbg prefixes IAT thunks with the branch mnemonic: JMP.&GetProcAddress
    const std::string lowered = to_lower(text);
    for (const char* mnemonic : {"jmp.", "call."}) {
        if (starts_with(lowered, mnemonic)) {
            text = text.substr(std::string(mnemonic).size());
            break;
        }
    }

    text = strip_wrappers(text);
    if (text.empty()) {
        return symbol;
    }

    // Split module from function on the last dot, but only when the tail is not
    // a file extension -- "kernel32.dll" alone must not yield function "dll".
    // Module names may themselves contain dots; apiset stubs do.
    std::string module_part;
    std::string function_part = text;
    const auto dot = text.rfind('.');
    if (dot != std::string::npos) {
        const std::string tail = to_lower(text.substr(dot + 1));
        if (tail == "dll" || tail == "exe" || tail == "sys" || tail == "drv") {
            module_part = text;
            function_part.clear();
        } else if (dot > 0) {
            module_part = text.substr(0, dot);
            function_part = text.substr(dot + 1);
        }
    }

    normalize_module(module_part, symbol.module, symbol.is_apiset);

    if (function_part.empty()) {
        return symbol;
    }

    if (function_part.front() == '#') {
        const std::string digits = function_part.substr(1);
        if (!digits.empty() && std::all_of(digits.begin(), digits.end(), is_digit)) {
            symbol.ordinal = std::stoi(digits);
        }
        return symbol;
    }

    function_part = strip_decoration(function_part);
    if (!is_identifier(function_part)) {
        return symbol;
    }

    symbol.function = function_part;
    symbol.lookup_keys = build_lookup_keys(function_part);
    symbol.canonical_key = canonical(function_part);
    return symbol;
}

}  // namespace malapi
