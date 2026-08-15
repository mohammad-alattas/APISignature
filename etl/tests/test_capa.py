"""Tests for capa rule compilation, the feature-program VM, and matching.

The compiler tests build tiny rule trees on disk so they assert behaviour rather
than the current contents of the vendored ruleset. The matching tests run against
the built index and are skipped when it is absent.
"""

from __future__ import annotations

import sqlite3
import sys
import textwrap
from pathlib import Path

import pytest

ETL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = ETL_DIR.parent
sys.path.insert(0, str(ETL_DIR))

import capabilities  # noqa: E402
from normalize import canonical  # noqa: E402
from sources import capa  # noqa: E402

DB_PATH = REPO_ROOT / "dist" / "apisignature.db"
needs_index = pytest.mark.skipif(
    not DB_PATH.exists(), reason="run etl/build_index.py first"
)


def compile_rules(tmp_path: Path, *sources: str) -> dict[str, capa.CapaRule]:
    for index, source in enumerate(sources):
        (tmp_path / f"rule{index}.yml").write_text(
            textwrap.dedent(source), encoding="utf-8"
        )
    return {rule.name: rule for rule in capa.load(tmp_path)}


def run(rule: capa.CapaRule, present: set[str], unknown_is_true: bool = False) -> bool:
    """Compile a rule's tree and evaluate it against a set of API names.

    ``present`` is canonicalized here so tests can be written with the readable
    spelling; rule.apis holds case-folded keys.
    """
    api_ids = {name: index for index, name in enumerate(sorted(rule.apis), start=1)}
    program = capa.emit_program(rule.tree, api_ids)
    present_ids = {
        api_ids[canonical(name)] for name in present if canonical(name) in api_ids
    }
    return capa.evaluate(program, present_ids, unknown_is_true=unknown_is_true)


RULE_TEMPLATE = """
rule:
  meta:
    name: {name}
    namespace: testing
    authors: [test]
    scopes:
      static: function
      dynamic: span of calls
  features:
{features}
"""


def make(name: str, features: str) -> str:
    return RULE_TEMPLATE.format(name=name, features=textwrap.indent(features, "    "))


# --------------------------------------------------------------------------
# Boolean semantics
# --------------------------------------------------------------------------


def test_and_requires_every_child(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make("both", "- and:\n  - api: kernel32.OpenProcess\n  - api: kernel32.WriteProcessMemory"),
    )
    rule = rules["both"]
    assert run(rule, {"OpenProcess", "WriteProcessMemory"}) is True
    assert run(rule, {"OpenProcess"}) is False
    assert run(rule, set()) is False


def test_or_requires_one_child(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make("either", "- or:\n  - api: kernel32.OpenProcess\n  - api: kernel32.CreateRemoteThread"),
    )
    rule = rules["either"]
    assert run(rule, {"OpenProcess"}) is True
    assert run(rule, {"CreateRemoteThread"}) is True
    assert run(rule, set()) is False


def test_not_inverts(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path, make("absent", "- not:\n  - api: kernel32.OpenProcess")
    )
    rule = rules["absent"]
    assert run(rule, set()) is True
    assert run(rule, {"OpenProcess"}) is False


def test_n_or_more_counts(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make(
            "atleast2",
            "- 2 or more:\n"
            "  - api: kernel32.OpenProcess\n"
            "  - api: kernel32.VirtualAllocEx\n"
            "  - api: kernel32.WriteProcessMemory",
        ),
    )
    rule = rules["atleast2"]
    assert run(rule, {"OpenProcess"}) is False
    assert run(rule, {"OpenProcess", "VirtualAllocEx"}) is True
    assert run(rule, {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory"}) is True


def test_optional_never_causes_failure(tmp_path: Path) -> None:
    """capa's `optional` is display-only and must not gate a match."""
    rules = compile_rules(
        tmp_path,
        make(
            "opt",
            "- and:\n"
            "  - api: kernel32.OpenProcess\n"
            "  - optional:\n"
            "    - api: kernel32.CreateRemoteThread",
        ),
    )
    rule = rules["opt"]
    assert run(rule, {"OpenProcess"}) is True
    # ...but the optional API is still advertised, so the panel can show it.
    assert canonical("CreateRemoteThread") in rule.apis


# --------------------------------------------------------------------------
# Non-API features
# --------------------------------------------------------------------------


def test_unknown_features_block_confirmation_but_allow_possibility(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make(
            "mixed",
            '- and:\n  - api: advapi32.RegSetValueEx\n  - string: "SOFTWARE\\\\Foo"',
        ),
    )
    rule = rules["mixed"]
    assert run(rule, {"RegSetValueEx"}, unknown_is_true=False) is False
    assert run(rule, {"RegSetValueEx"}, unknown_is_true=True) is True
    assert rule.has_unknown is True


def test_os_and_format_resolve_instead_of_becoming_unknown(tmp_path: Path) -> None:
    """We always run on Windows against a PE, so these are decidable."""
    rules = compile_rules(
        tmp_path,
        make("win", "- and:\n  - os: windows\n  - api: kernel32.OpenProcess"),
        make("lin", "- and:\n  - os: linux\n  - api: kernel32.OpenProcess"),
        make("pe", "- and:\n  - format: pe\n  - api: kernel32.OpenProcess"),
    )
    assert run(rules["win"], {"OpenProcess"}) is True
    assert run(rules["lin"], {"OpenProcess"}) is False
    assert run(rules["pe"], {"OpenProcess"}) is True
    # Resolved, not deferred.
    assert rules["win"].has_unknown is False


def test_leaf_counts_separate_api_only_from_mixed_rules(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make("pure", "- and:\n  - api: kernel32.OpenProcess\n  - api: kernel32.VirtualAllocEx"),
        make("mixed", '- and:\n  - api: kernel32.OpenProcess\n  - string: "x"\n  - number: 0x40'),
    )
    assert rules["pure"].leaf_counts() == (2, 0)
    assert rules["mixed"].leaf_counts() == (1, 2)


# --------------------------------------------------------------------------
# Rule references
# --------------------------------------------------------------------------


def test_match_inlines_referenced_rule(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make("write memory", "- api: kernel32.WriteProcessMemory"),
        make("uses it", "- and:\n  - match: write memory\n  - api: kernel32.OpenProcess"),
    )
    rule = rules["uses it"]
    assert run(rule, {"WriteProcessMemory", "OpenProcess"}) is True
    assert run(rule, {"OpenProcess"}) is False
    assert set(rule.apis) == {canonical("WriteProcessMemory"), canonical("OpenProcess")}


def test_match_on_namespace_expands_to_all_members(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        RULE_TEMPLATE.format(
            name="alpha",
            features="    - api: kernel32.OpenProcess",
        ).replace("namespace: testing", "namespace: family/sub"),
        RULE_TEMPLATE.format(
            name="beta",
            features="    - api: kernel32.VirtualAllocEx",
        ).replace("namespace: testing", "namespace: family/sub"),
        make("consumer", "- match: family"),
    )
    rule = rules["consumer"]
    assert run(rule, {"OpenProcess"}) is True
    assert run(rule, {"VirtualAllocEx"}) is True
    assert run(rule, set()) is False


def test_recursive_match_does_not_hang(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make("a", "- or:\n  - match: b\n  - api: kernel32.OpenProcess"),
        make("b", "- or:\n  - match: a\n  - api: kernel32.VirtualAllocEx"),
    )
    assert run(rules["a"], {"OpenProcess"}) is True
    assert rules["a"].has_unknown is True  # the back-edge became UNKNOWN


# --------------------------------------------------------------------------
# API feature normalization
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("kernel32.VirtualAllocEx", "virtualallocex"),
        ("VirtualAllocEx", "virtualallocex"),
        ("kernel32.CreateProcessW", "createprocess"),
        ("ntdll.ZwOpenProcess", "ntopenprocess"),
        ("System.IO.File::Delete", "System.IO.File::Delete"),
        ("", None),
    ],
)
def test_normalize_api_feature(value: str, expected: str | None) -> None:
    assert capa.normalize_api_feature(value) == expected


def test_technique_parsing() -> None:
    parsed = capa._parse_technique(
        "Defense Evasion::Process Injection::Asynchronous Procedure Call [T1055.004]"
    )
    assert parsed["id"] == "T1055.004"
    assert parsed["text"] == (
        "Defense Evasion::Process Injection::Asynchronous Procedure Call"
    )


# --------------------------------------------------------------------------
# Program VM
# --------------------------------------------------------------------------


def test_program_is_postfix_and_stack_balanced(tmp_path: Path) -> None:
    rules = compile_rules(
        tmp_path,
        make(
            "nested",
            "- and:\n"
            "  - or:\n"
            "    - api: kernel32.OpenProcess\n"
            "    - api: kernel32.VirtualAllocEx\n"
            "  - not:\n"
            "    - api: kernel32.ExitProcess",
        ),
    )
    rule = rules["nested"]
    assert run(rule, {"OpenProcess"}) is True
    assert run(rule, {"OpenProcess", "ExitProcess"}) is False


def test_evaluate_rejects_a_malformed_program() -> None:
    with pytest.raises(ValueError):
        capa.evaluate(b"\xff", set(), unknown_is_true=False)


# --------------------------------------------------------------------------
# Matching against the built index
# --------------------------------------------------------------------------


@pytest.fixture()
def conn() -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    yield connection
    connection.close()


@needs_index
def test_injection_chain_surfaces_injection(conn: sqlite3.Connection) -> None:
    found = capabilities.match(
        conn,
        {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
    )
    names = [c.name for c in found]
    assert "inject thread" in names


@needs_index
def test_benign_api_set_raises_nothing_alarming(conn: sqlite3.Connection) -> None:
    found = capabilities.match(
        conn, {"GetCommandLine", "MessageBox", "ExitProcess", "GetStdHandle"}
    )
    assert [c.name for c in found if "inject" in c.name.lower()] == []


@needs_index
def test_high_confidence_tier_is_clean_on_notepad(conn: sqlite3.Connection) -> None:
    """The regression that drove the tiered model.

    Granting unchecked features made notepad.exe match "bypass UAC" and "disable
    Windows Defender", because those rules are discriminated by a registry path
    string rather than by their APIs. The API-only tier must stay clean.
    """
    notepad = Path(r"C:\Windows\System32\notepad.exe")
    if not notepad.exists():
        pytest.skip("notepad.exe not available")

    imports = capabilities.imports_from_pe(notepad)
    strict = capabilities.match(
        conn, imports, min_confidence=capabilities.CONFIDENCE_HIGH
    )
    assert strict, "expected some capabilities for a real binary"
    assert all(c.confidence == capabilities.CONFIDENCE_HIGH for c in strict)

    alarming = [
        c.name
        for c in strict
        if any(w in c.name.lower() for w in ("inject", "bypass uac", "disable", "keylog"))
    ]
    assert alarming == []


@needs_index
def test_rules_for_api_marks_present_and_absent(conn: sqlite3.Connection) -> None:
    rules = capabilities.rules_for_api(
        conn, "VirtualAllocEx", present={"VirtualAllocEx", "WriteProcessMemory"}
    )
    assert rules
    for rule in rules:
        assert canonical("VirtualAllocEx") in rule.present_apis
        assert not set(rule.present_apis) & set(rule.absent_apis)


@needs_index
def test_rules_for_api_folds_the_lookup_name(conn: sqlite3.Connection) -> None:
    """A W-spelling from the disassembly must reach the same combinations."""
    assert capabilities.rules_for_api(conn, "CreateProcessW") == (
        capabilities.rules_for_api(conn, "CreateProcessA")
    )


@needs_index
def test_unknown_api_yields_no_combinations(conn: sqlite3.Connection) -> None:
    assert capabilities.rules_for_api(conn, "NotARealApiXyz") == []
