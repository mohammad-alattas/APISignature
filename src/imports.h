// The debuggee's imported API names, read out of its memory.
//
// Read from memory rather than from the file on disk, because the file on disk
// is often not what is running: packed samples rebuild their own import table
// after unpacking, and a manually mapped module never had one on disk at all.
// What the process actually resolved is the thing worth matching capa against.

#pragma once

#include <set>
#include <string>

#include "bridgemain.h"

namespace malapi {

// Base address of the debuggee's main module, or 0 when nothing is running.
duint main_module_base();

// Imported function names for the module at `base`, canonicalized so they can be
// compared against capa_api.name_norm directly. Empty when nothing is loaded or
// the headers do not parse.
std::set<std::string> imported_apis(duint base);

// The union across every module currently loaded in the debuggee.
//
// This is what makes a capability view worth re-running. The main module's
// import table is fixed at load, so re-reading it can never say anything new;
// but a packed sample unpacks and then loads more DLLs, and each one arrives
// with its own imports. Scanning them all is what lets the answer grow as
// execution proceeds.
std::set<std::string> all_imported_apis();

}  // namespace malapi
