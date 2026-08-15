#include "imports.h"

#include <windows.h>

#include <vector>

#include "_plugins.h"
#include "_scriptapi_module.h"
#include "bridgelist.h"
#include "normalize.h"

namespace malapi {
namespace {

// Every field comes from the debuggee, so nothing here may be trusted. Each read
// is bounds-checked and every loop is capped: a malformed or deliberately
// hostile header must produce a short list, never a hang or an out-of-range
// read. Samples do craft broken headers specifically to break tooling.
constexpr size_t kMaxDescriptors = 4096;
constexpr size_t kMaxThunksPerModule = 65536;
constexpr size_t kMaxNameLength = 256;

template <typename T>
bool read(duint address, T& out) {
    return DbgMemRead(address, &out, sizeof(T));
}

// Import names are NUL-terminated and of unknown length, so read a window and
// stop at the terminator. A name running to the end of the window is discarded
// rather than truncated -- a wrong API name is worse than a missing one.
bool read_name(duint address, std::string& out) {
    char buffer[kMaxNameLength] = {};
    if (!DbgMemRead(address, buffer, sizeof(buffer) - 1)) {
        // Near the end of a page the full window may not be readable; retry
        // with a smaller one before giving up.
        if (!DbgMemRead(address, buffer, 64)) {
            return false;
        }
        buffer[63] = '\0';
    }

    const size_t length = strnlen(buffer, sizeof(buffer) - 1);
    if (length == 0 || length >= sizeof(buffer) - 1) {
        return false;
    }
    out.assign(buffer, length);
    return true;
}

}  // namespace

duint main_module_base() {
    if (!DbgIsDebugging()) {
        return 0;
    }
    return Script::Module::GetMainModuleBase();
}

std::set<std::string> all_imported_apis() {
    std::set<std::string> names;
    if (!DbgIsDebugging()) {
        return names;
    }

    BridgeList<Script::Module::ModuleInfo> modules;
    if (!Script::Module::GetList(&modules)) {
        // Fall back to the main module rather than reporting nothing: a partial
        // capability view is still useful, an empty one looks like a clean file.
        return imported_apis(main_module_base());
    }

    for (int index = 0; index < modules.Count(); ++index) {
        const std::set<std::string> module_names = imported_apis(modules[index].base);
        names.insert(module_names.begin(), module_names.end());
    }
    return names;
}

std::set<std::string> imported_apis(duint base) {
    std::set<std::string> names;
    if (!base || !DbgIsDebugging()) {
        return names;
    }

    IMAGE_DOS_HEADER dos{};
    if (!read(base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        return names;
    }

    // x64dbg debugs same-architecture processes only -- x32dbg handles 32-bit --
    // so the native header layout is always the right one here.
    IMAGE_NT_HEADERS nt{};
    if (!read(base + static_cast<duint>(dos.e_lfanew), nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return names;
    }

    const IMAGE_DATA_DIRECTORY& directory =
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || !directory.Size) {
        return names;  // no imports, or they were stripped
    }

    duint descriptor_at = base + directory.VirtualAddress;
    for (size_t index = 0; index < kMaxDescriptors; ++index,
                descriptor_at += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (!read(descriptor_at, descriptor)) {
            break;
        }
        if (!descriptor.Name && !descriptor.FirstThunk) {
            break;  // the terminating null descriptor
        }

        // OriginalFirstThunk still holds names after the loader has overwritten
        // FirstThunk with addresses; fall back for binaries that lack it.
        const DWORD thunk_rva = descriptor.OriginalFirstThunk
                                    ? descriptor.OriginalFirstThunk
                                    : descriptor.FirstThunk;
        if (!thunk_rva) {
            continue;
        }

        duint thunk_at = base + thunk_rva;
        for (size_t slot = 0; slot < kMaxThunksPerModule;
             ++slot, thunk_at += sizeof(duint)) {
            duint thunk = 0;
            if (!read(thunk_at, thunk) || thunk == 0) {
                break;
            }

            // The high bit marks an ordinal import, which carries no name. capa
            // rules are written against names, so these are simply not matchable
            // and are skipped rather than guessed at.
            if (thunk & (static_cast<duint>(1) << (sizeof(duint) * 8 - 1))) {
                continue;
            }

            std::string name;
            if (read_name(base + thunk + offsetof(IMAGE_IMPORT_BY_NAME, Name), name)) {
                // Canonical form, so these compare directly against
                // capa_api.name_norm without folding at every comparison.
                names.insert(canonical(name));
            }
        }
    }

    return names;
}

}  // namespace malapi
