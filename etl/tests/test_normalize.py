"""Tests for the API name normalizer.

Two layers here:

  * ``test_fixture_*`` assert the shared contract in ``normalize_cases.json``.
    ``src/normalize.cpp`` is asserted against the same file, so a change that
    passes here but is not mirrored in C++ will fail there.
  * ``test_malapi_*`` assert the properties that actually matter against the real
    ``malapi.json``, rather than against a hand-picked sample. These are the ones
    that would have caught DnsQuery_A.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ETL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ETL_DIR))

from normalize import (  # noqa: E402
    canonical,
    fold_charset_suffix,
    fold_zw_to_nt,
    is_native_api,
    parse_symbol,
    strip_decoration,
)

FIXTURES = json.loads(
    (ETL_DIR / "tests" / "normalize_cases.json").read_text(encoding="utf-8")
)["cases"]

MALAPI = json.loads(
    (ETL_DIR.parent / "malapi.json").read_text(encoding="utf-8")
)
MALAPI_NAMES = {entry["name"] for entry in MALAPI}


def _norm_index() -> dict[str, list[str]]:
    """Emulate the index's ``name_norm`` column."""
    index: dict[str, list[str]] = {}
    for name in MALAPI_NAMES:
        index.setdefault(canonical(name), []).append(name)
    return index


NORM_INDEX = _norm_index()


def resolve(raw: str) -> str | None:
    """Emulate the plugin's two-stage lookup: exact name, then canonical key."""
    symbol = parse_symbol(raw)
    for key in symbol.lookup_keys:
        if key in MALAPI_NAMES:
            return key
    if symbol.canonical_key in NORM_INDEX:
        return NORM_INDEX[symbol.canonical_key][0]
    return None


# --------------------------------------------------------------------------
# Shared contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", FIXTURES, ids=lambda c: c["raw"] or "<empty>")
def test_fixture_matches_contract(case: dict) -> None:
    sym = parse_symbol(case["raw"])
    assert sym.module == case["module"]
    assert sym.function == case["function"]
    assert sym.ordinal == case["ordinal"]
    assert sym.is_apiset == case["is_apiset"]
    assert sym.lookup_keys == case["keys"]
    assert sym.canonical_key == case["canonical"]


# --------------------------------------------------------------------------
# Properties asserted against the real dataset
# --------------------------------------------------------------------------


def test_every_entry_resolves_to_itself() -> None:
    """No entry may be shadowed by another entry's folded form."""
    unreachable = [n for n in sorted(MALAPI_NAMES) if resolve(n) != n]
    assert unreachable == []


def test_ansi_only_entries_reachable_from_unicode_spelling() -> None:
    """The core A/W problem: 122 entries exist only under their ANSI name.

    An analyst stepping through a modern binary sees the W spelling, so every one
    of those entries must be reachable from it or the panel is blank.
    """
    ansi_only = sorted(
        n for n in MALAPI_NAMES
        if n.endswith("A") and canonical(n) != n and n[:-1] + "W" not in MALAPI_NAMES
    )
    assert len(ansi_only) == 122, "dataset shape changed; revisit the fold rules"

    unreachable = [n for n in ansi_only if resolve(canonical(n) + "W") != n]
    assert unreachable == []


def test_native_apis_reachable_from_zw_spelling() -> None:
    """ntdll exports Nt and Zw at the same address; MalAPI only stores Nt."""
    nt_names = sorted(n for n in MALAPI_NAMES if n.startswith("Nt"))
    assert nt_names, "expected Nt* entries in the dataset"
    unreachable = [n for n in nt_names if resolve("Zw" + n[2:]) != n]
    assert unreachable == []


def test_no_canonical_key_collisions() -> None:
    """Two distinct APIs must never fold onto the same key."""
    collisions = {k: v for k, v in NORM_INDEX.items() if len(v) > 1}
    assert collisions == {}


def test_dnsquery_underscore_variant() -> None:
    """Regression: the underscore before the charset suffix defeated the fold."""
    assert canonical("DnsQuery_A") == "dnsquery"
    assert canonical("DnsQuery_W") == "dnsquery"
    assert resolve("DnsQuery_W") == "DnsQuery_A"


def test_winsock_case_mismatch_is_folded() -> None:
    """Regression: MalAPI title-cases Winsock, the real exports are lowercase.

    Selecting `ws2_32.socket` in the disassembly has to reach MalAPI's `Socket`
    entry, or the intent layer is missing for the whole Internet category.
    """
    for titled in ("Socket", "Accept", "Recv", "Listen", "Closesocket"):
        assert canonical(titled) == canonical(titled.lower())
    assert resolve("ws2_32.socket") == "Socket"
    assert resolve("recv") == "Recv"


def test_canonical_is_case_insensitive_but_folds_first() -> None:
    """GetKeynameTextA (MalAPI) and GetKeyNameTextA (Microsoft) must unify."""
    assert canonical("GetKeynameTextA") == canonical("GetKeyNameTextA")
    # Folding still happens before lowercasing, so acronyms survive.
    assert fold_charset_suffix("RSA") == "RSA"


# --------------------------------------------------------------------------
# Unit-level behaviour
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("__imp_CreateProcessW", "CreateProcessW"),
        ("_imp_CreateProcessW", "CreateProcessW"),
        ("_VirtualAllocEx@20", "VirtualAllocEx"),
        ("VirtualAllocEx", "VirtualAllocEx"),
    ],
)
def test_strip_decoration(raw: str, expected: str) -> None:
    assert strip_decoration(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CreateProcessW", "CreateProcess"),
        ("CreateProcessA", "CreateProcess"),
        ("CopyFileExW", "CopyFileEx"),
        ("DnsQuery_A", "DnsQuery"),
        ("VirtualAllocEx", "VirtualAllocEx"),
        ("ShowWindow", "ShowWindow"),
        ("RSA", "RSA"),
    ],
)
def test_fold_charset_suffix(raw: str, expected: str) -> None:
    assert fold_charset_suffix(raw) == expected


def test_ex_suffix_never_collapses() -> None:
    """VirtualAlloc and VirtualAllocEx are different functions."""
    assert canonical("VirtualAlloc") != canonical("VirtualAllocEx")
    assert canonical("GetVersionEx") != canonical("GetVersion")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ZwOpenProcess", "NtOpenProcess"),
        ("NtOpenProcess", "NtOpenProcess"),
        ("ZwProtectVirtualMemory", "NtProtectVirtualMemory"),
    ],
)
def test_fold_zw_to_nt(raw: str, expected: str) -> None:
    assert fold_zw_to_nt(raw) == expected


@pytest.mark.parametrize(
    "name,native",
    [
        ("NtOpenProcess", True),
        ("ZwOpenProcess", True),
        ("RtlMoveMemory", True),
        ("LdrLoadDll", True),
        ("CreateProcessW", False),
        ("Network", False),
    ],
)
def test_is_native_api(name: str, native: bool) -> None:
    assert is_native_api(name) is native


def test_native_apis_get_no_charset_siblings() -> None:
    """NtOpenProcessA does not exist; do not waste lookups on it."""
    keys = parse_symbol("NtOpenProcess").lookup_keys
    assert not any(k.endswith(("A", "W")) and k != "NtOpenProcess" for k in keys)


def test_apiset_module_is_dropped_not_guessed() -> None:
    """An apiset stub names no implementing DLL, so module must be None."""
    sym = parse_symbol("api-ms-win-core-processthreads-l1-1-0.CreateProcessW")
    assert sym.module is None
    assert sym.is_apiset is True
    assert sym.function == "CreateProcessW"


def test_forwarder_module_folds_to_implementer() -> None:
    assert parse_symbol("KERNELBASE.VirtualAllocEx").module == "kernel32"


def test_unresolvable_inputs_are_not_resolvable() -> None:
    for raw in ("", "   ", "kernel32.dll", "#42", "kernel32.#123"):
        assert parse_symbol(raw).resolvable is False
