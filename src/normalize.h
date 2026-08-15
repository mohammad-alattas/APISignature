// Windows API name normalization.
//
// Mirror of etl/normalize.py. Both are asserted against
// etl/tests/normalize_cases.json -- change the fixture table first, then both
// implementations, or the index and the lookup will quietly disagree.
//
// Two facts about the data drive everything here:
//
//   * malapi.json lists 122 APIs under their `A` spelling and none under `W`,
//     while a modern disassembly shows the `W` spelling almost exclusively.
//   * ntdll exports NtX and ZwX at the same address, and MalAPI only uses Nt.

#pragma once

#include <string>
#include <vector>

namespace malapi {

struct Symbol {
    std::string raw;
    std::string function;   // undecorated name; empty when unresolvable
    std::string module;     // normalized; empty when unknown or an apiset stub
    int ordinal = -1;       // for #N exports; -1 when not an ordinal
    bool is_apiset = false;

    // Case-preserving exact spellings to try against api.name, most specific
    // first.
    std::vector<std::string> lookup_keys;

    // Single case-folded key to try against api.name_norm once every exact
    // spelling has missed. All of lookup_keys reduce to this one value.
    std::string canonical_key;

    bool resolvable() const { return !lookup_keys.empty(); }
};

// Remove import-thunk and stdcall decoration:
//   __imp_CreateProcessW -> CreateProcessW
//   _VirtualAllocEx@20   -> VirtualAllocEx
std::string strip_decoration(const std::string& name);

// Fold an ANSI/Unicode variant onto its base name. CreateProcessW and
// CreateProcessA both fold to CreateProcess; DnsQuery_A folds to DnsQuery. The
// Ex suffix is preserved -- VirtualAlloc and VirtualAllocEx are different calls.
std::string fold_charset_suffix(const std::string& name);

// ZwOpenProcess -> NtOpenProcess.
std::string fold_zw_to_nt(const std::string& name);

// The key stored in api.name_norm, applied identically at build and lookup time.
std::string canonical(const std::string& name);

// True for ntdll-style natives, which have no ANSI/Unicode spellings.
bool is_native_api(const std::string& function);

// Normalize a module name. Returns false in `is_apiset` unless the name was an
// api-ms-win-/ext-ms-win- stub, in which case the module is cleared: the stub
// names no implementing DLL.
void normalize_module(const std::string& module, std::string& out, bool& is_apiset);

// Parse whatever x64dbg puts on screen into its addressable parts. Handles
// bare names, module.Export, <&Export>, JMP.&Export, memory operands such as
// "qword ptr ds:[<&CreateProcessW>]", decorated symbols and #N ordinals.
Symbol parse_symbol(const std::string& raw);

}  // namespace malapi
