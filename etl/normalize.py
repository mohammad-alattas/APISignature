"""Windows API name normalization.

Single source of truth for turning whatever x64dbg puts in front of the analyst --
an export label, an IAT thunk, a stdcall-decorated symbol -- into an ordered list
of keys to look up in the index.

Two facts about the source data drive everything here:

  * malapi.json lists 122 APIs under their ``A`` spelling and *none* under ``W``.
    At runtime you overwhelmingly see ``CreateProcessW``. Without A/W folding the
    panel is blank for the common case.
  * ntdll exports ``NtX`` and ``ZwX`` at the same address, and MalAPI only ever
    uses the ``Nt`` spelling.

``src/normalize.cpp`` mirrors this file. Both are asserted against
``tests/normalize_cases.json`` -- when behaviour needs to change, change the
fixture table first, then both implementations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Apiset stub names (api-ms-win-core-processthreads-l1-1-1, ext-ms-win-...) never
# name the DLL that actually implements the call, so they are recorded and then
# ignored for lookup purposes.
_APISET_RE = re.compile(r"^(?:api|ext)-ms-win-", re.IGNORECASE)

# 32-bit stdcall decoration: _VirtualAllocEx@20
_STDCALL_RE = re.compile(r"^_(?P<name>[A-Za-z_][A-Za-z0-9_]*)@\d+$")

# Ordinal-only exports: #123 or kernel32.#123
_ORDINAL_RE = re.compile(r"^#(?P<ordinal>\d+)$")

# A bare identifier. Anything that fails this is not a symbol we can look up.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Modules that forward to, or are implementation details of, another module.
# Used only to make the panel say something sensible about provenance -- module
# is advisory metadata, never a lookup filter, because apiset and forwarder
# chains make any strict DLL match wrong more often than right.
_MODULE_ALIASES = {
    "kernelbase": "kernel32",
    "ntoskrnl": "ntdll",
    "wow64win": "win32u",
    "sechost": "advapi32",
}

# Native API prefixes. These functions take UNICODE_STRING and have no ANSI or
# Unicode spellings, so expanding A/W siblings for them yields keys that can
# never hit (NtOpenProcessA does not exist).
_NATIVE_PREFIXES = ("Nt", "Zw", "Rtl", "Ldr", "Ke", "Csr", "Dbg")

# Function names ending in an uppercase A or W that are NOT charset variants.
# Empty today; kept as the documented escape hatch so a future false fold has an
# obvious home rather than becoming a special case inside fold_charset_suffix.
_NOT_CHARSET_VARIANTS: frozenset[str] = frozenset()


@dataclass
class Symbol:
    """A parsed symbol reference, split into its addressable parts."""

    raw: str
    function: str = ""
    module: str | None = None
    ordinal: int | None = None
    is_apiset: bool = False
    #: Case-preserving exact spellings to try against ``api.name``, most
    #: specific first.
    lookup_keys: list[str] = field(default_factory=list)
    #: Single case-folded key to try against ``api.name_norm`` once every exact
    #: spelling has missed. All of ``lookup_keys`` reduce to this one value.
    canonical_key: str = ""

    @property
    def resolvable(self) -> bool:
        return bool(self.lookup_keys)


def strip_decoration(name: str) -> str:
    """Remove import-thunk and stdcall decoration from a symbol name.

    ``__imp_CreateProcessW`` -> ``CreateProcessW``
    ``_VirtualAllocEx@20``   -> ``VirtualAllocEx``
    """
    name = name.strip()
    for prefix in ("__imp__", "__imp_", "_imp__", "_imp_"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break

    stdcall = _STDCALL_RE.match(name)
    if stdcall:
        name = stdcall.group("name")

    return name


def fold_charset_suffix(name: str) -> str:
    """Fold an ANSI/Unicode variant onto its base name.

    ``CreateProcessW`` and ``CreateProcessA`` both fold to ``CreateProcess``;
    ``CopyFileExW`` folds to ``CopyFileEx``. The ``Ex`` suffix is deliberately
    preserved -- ``VirtualAlloc`` and ``VirtualAllocEx`` are different functions
    and must never collapse together.

    The trailing letter only counts as a charset marker when the character before
    it is lowercase, a digit, or an underscore. That keeps all-caps acronyms
    intact -- a hypothetical ``RSA`` ends in ``A`` but ``S`` is uppercase, so it
    is left alone -- while still catching dnsapi's underscore-separated
    ``DnsQuery_A`` / ``DnsQuery_W`` pair, which is otherwise unreachable.
    """
    if name in _NOT_CHARSET_VARIANTS:
        return name
    if len(name) < 2 or name[-1] not in ("A", "W"):
        return name

    preceding = name[-2]
    if preceding.islower() or preceding.isdigit():
        return name[:-1]
    if preceding == "_" and len(name) > 2:
        # DnsQuery_A -> DnsQuery, so both spellings share one canonical key.
        return name[:-2]
    return name


def fold_zw_to_nt(name: str) -> str:
    """Fold the ``Zw`` spelling of a native API onto its ``Nt`` twin.

    ntdll exports both at the same address and MalAPI only ever uses ``Nt``, so
    ``ZwOpenProcess`` has to reach the ``NtOpenProcess`` entry. Guarded on a
    following uppercase letter so an unrelated name starting with "Zw" is safe.
    """
    if len(name) > 2 and name.startswith("Zw") and name[2].isupper():
        return "Nt" + name[2:]
    return name


def canonical(name: str) -> str:
    """Reduce a function name to the key stored in ``api.name_norm``.

    Applied identically at index-build time and at lookup time, which is what
    makes the two sides meet.

    Case-folded last, and deliberately. MalAPI title-cases the Winsock family --
    ``Socket``, ``Accept``, ``Recv``, ``Listen``, ``Closesocket`` -- while the
    real exports and Microsoft's own pages are lowercase, and it writes
    ``GetKeynameTextA`` where Microsoft has ``GetKeyNameTextA``. A case-sensitive
    key leaves the malicious-intent layer unreachable for every one of them.

    Folding happens before lowercasing because the A/W and Zw rules need the
    original case to tell a charset suffix from an acronym.
    """
    return fold_zw_to_nt(fold_charset_suffix(strip_decoration(name))).lower()


def normalize_module(module: str | None) -> tuple[str | None, bool]:
    """Normalize a module name, reporting whether it was an apiset stub.

    Returns ``(module_or_None, is_apiset)``. Apiset stubs resolve to ``None``
    because the stub name tells you nothing about the implementing DLL.
    """
    if not module:
        return None, False

    module = module.strip().strip("<>&").lower()
    for suffix in (".dll", ".exe", ".sys", ".drv", ".lib"):
        if module.endswith(suffix):
            module = module[: -len(suffix)]

    if _APISET_RE.match(module):
        return None, True
    if not module:
        return None, False

    return _MODULE_ALIASES.get(module, module), False


def parse_symbol(raw: str) -> Symbol:
    """Parse anything x64dbg might hand us into a :class:`Symbol`.

    Handles the shapes that actually turn up in the disassembly view::

        VirtualAllocEx
        kernel32.VirtualAllocEx
        <kernel32.VirtualAllocEx>
        JMP.&GetProcAddress
        qword ptr ds:[<&CreateProcessW>]
        __imp_CreateProcessW
        _VirtualAllocEx@20
        kernel32.#123
    """
    sym = Symbol(raw=raw)
    text = (raw or "").strip()
    if not text:
        return sym

    # Pull the symbol out of a memory operand: ds:[<&CreateProcessW>] and friends.
    bracketed = re.search(r"\[([^\[\]]+)\]", text)
    if bracketed:
        text = bracketed.group(1)

    text = text.strip().strip("<>").lstrip("&").strip()

    # x64dbg prefixes IAT thunks with the branch mnemonic: JMP.&GetProcAddress
    for mnemonic in ("jmp.", "call."):
        if text.lower().startswith(mnemonic):
            text = text[len(mnemonic) :].lstrip("&")
            break

    text = text.strip().strip("<>").lstrip("&").strip()
    if not text:
        return sym

    # Split module from function on the last dot, but only when the tail is not
    # itself a file extension -- "kernel32.dll" alone must not become function
    # "dll". Module names themselves may contain dots (apiset stubs do).
    module_part: str | None = None
    function_part = text
    if "." in text:
        head, _, tail = text.rpartition(".")
        if tail.lower() in ("dll", "exe", "sys", "drv"):
            module_part, function_part = text, ""
        elif head:
            module_part, function_part = head, tail

    sym.module, sym.is_apiset = normalize_module(module_part)

    if not function_part:
        return sym

    ordinal = _ORDINAL_RE.match(function_part)
    if ordinal:
        sym.ordinal = int(ordinal.group("ordinal"))
        return sym

    function_part = strip_decoration(function_part)
    if not _IDENT_RE.match(function_part):
        return sym

    sym.function = function_part
    sym.lookup_keys = _build_lookup_keys(function_part)
    sym.canonical_key = canonical(function_part)
    return sym


def is_native_api(function: str) -> bool:
    """True for ntdll-style natives, which have no ANSI/Unicode variants."""
    return any(
        function.startswith(p) and len(function) > len(p) and function[len(p)].isupper()
        for p in _NATIVE_PREFIXES
    )


def _build_lookup_keys(function: str) -> list[str]:
    """Ordered exact-spelling candidates, most specific first.

    These are matched against ``api.name``, so they keep their original case; the
    case-folded fallback lives in :attr:`Symbol.canonical_key` and is tried only
    after all of these miss.

    The exact spelling comes first, so ``CreateProcessA`` lands on the ANSI entry
    directly instead of arriving there via the base name. Charset siblings expand
    in both directions: W->A reaches MalAPI's 122 ANSI-only entries from the
    spelling seen at runtime, and bare->A/W lets a capa rule written as
    ``api: CreateProcess`` match a row stored as ``CreateProcessA``.
    """
    keys: list[str] = []

    def push(key: str) -> None:
        if key and key not in keys:
            keys.append(key)

    base = fold_charset_suffix(function)

    push(function)
    push(fold_zw_to_nt(function))
    push(base)

    if not is_native_api(function):
        push(base + "A")
        push(base + "W")

    return keys


def lookup_keys(raw: str) -> list[str]:
    """Convenience wrapper: parse ``raw`` and return just its lookup keys."""
    return parse_symbol(raw).lookup_keys
