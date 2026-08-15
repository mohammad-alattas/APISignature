#!/usr/bin/env python3
"""Match a target's API set against capa rules -- the API-combination layer.

Reference implementation for ``src/capa_eval.cpp``. Also runnable directly, so
the matcher can be exercised against a real PE without x64dbg:

    python etl/capabilities.py --pe C:\\Windows\\System32\\notepad.exe
    python etl/capabilities.py OpenProcess VirtualAllocEx WriteProcessMemory \\
                               CreateRemoteThread

**On what "matched" honestly means.** capa rules are precise because they check
constants alongside APIs -- ``VirtualAlloc`` *plus* ``number: 0x40`` for
PAGE_EXECUTE_READWRITE. An import table has APIs and no constants, so demanding
that every feature be provable makes almost every rule unsatisfiable: against the
classic injection chain, zero of 1054 rules verify end to end.

So a rule is reported when both hold:

  * its API skeleton is satisfied -- the tree evaluates true when the features we
    cannot check are granted, and
  * at least one of its APIs is genuinely present, so it cannot ride in on
    unknowns alone.

Results are ranked by how many of the rule's APIs actually matched. Two caveats
belong in front of the analyst, not buried here: capa's static scope wants those
APIs in the *same function*, while an import set only proves they exist somewhere
in the binary; and a rule whose non-API features we could not check is evidence
of capability, not proof of behaviour.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

ETL_DIR = Path(__file__).resolve().parent
REPO_ROOT = ETL_DIR.parent
sys.path.insert(0, str(ETL_DIR))

from normalize import canonical  # noqa: E402
from sources.capa import evaluate  # noqa: E402

DEFAULT_DB = REPO_ROOT / "dist" / "apisignature.db"


#: Decided entirely by API features, so an import table answers it as soundly as
#: it answers anything. 279 of 1033 non-library rules qualify.
CONFIDENCE_HIGH = "high"

#: The rule's API requirements are met, but capa also tests strings, constants or
#: instructions the import table cannot show. Real signal, weak evidence: this is
#: the tier where "persist via Print Processors" fires on notepad.exe because the
#: registry path that actually identifies the technique is invisible to us.
CONFIDENCE_PARTIAL = "partial"


@dataclass
class Capability:
    """One rule that the target's API set supports."""

    name: str
    namespace: str | None
    description: str | None
    confidence: str = CONFIDENCE_PARTIAL
    attck: list[dict] = field(default_factory=list)
    mbc: list[dict] = field(default_factory=list)
    matched_apis: list[str] = field(default_factory=list)
    missing_apis: list[str] = field(default_factory=list)
    #: Leaves capa would test that an import table cannot answer.
    unknown_leaves: int = 0

    @property
    def score(self) -> int:
        return len(self.matched_apis)


@dataclass
class RuleForApi:
    """A combination the selected API participates in.

    The panel's primary capability view. Rather than asserting a verdict about
    the binary, it shows the whole combination and marks which parts are present,
    which is both more useful at a breakpoint and impossible to overstate.
    """

    name: str
    namespace: str | None
    attck: list[dict] = field(default_factory=list)
    mbc: list[dict] = field(default_factory=list)
    present_apis: list[str] = field(default_factory=list)
    absent_apis: list[str] = field(default_factory=list)
    confidence: str = CONFIDENCE_PARTIAL
    unknown_leaves: int = 0

    @property
    def completeness(self) -> float:
        total = len(self.present_apis) + len(self.absent_apis)
        return len(self.present_apis) / total if total else 0.0


def _present_ids(conn: sqlite3.Connection, present_norm: set[str]) -> set[int]:
    if not present_norm:
        return set()
    placeholders = ",".join("?" * len(present_norm))
    return {
        row[0]
        for row in conn.execute(
            f"SELECT id FROM capa_api WHERE name_norm IN ({placeholders})",
            tuple(sorted(present_norm)),
        )
    }


def _rule_apis(conn: sqlite3.Connection, rule_id: int) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "SELECT ca.name_norm FROM capa_rule_api ra"
            " JOIN capa_api ca ON ca.id = ra.capa_api_id"
            " WHERE ra.rule_id = ? ORDER BY ca.name_norm",
            (rule_id,),
        )
    ]


def match(
    conn: sqlite3.Connection,
    api_names: set[str],
    min_confidence: str = CONFIDENCE_PARTIAL,
) -> list[Capability]:
    """Rank the capabilities supported by ``api_names``.

    Pass ``min_confidence=CONFIDENCE_HIGH`` for the trustworthy subset. On
    notepad.exe that is the difference between 19 accurate capabilities and 152
    that include "bypass UAC".
    """
    present_norm = {canonical(name) for name in api_names if name}
    present_ids = _present_ids(conn, present_norm)
    if not present_ids:
        return []

    results: list[Capability] = []
    for row in conn.execute(
        "SELECT id, name, namespace, description, attck_json, mbc_json,"
        "       program, unknown_leaves"
        " FROM capa_rule WHERE is_lib = 0 AND api_leaves > 0"
    ).fetchall():
        rule_id, name, namespace, description, attck, mbc, program, unknown = row

        confidence = CONFIDENCE_HIGH if unknown == 0 else CONFIDENCE_PARTIAL
        if min_confidence == CONFIDENCE_HIGH and confidence != CONFIDENCE_HIGH:
            continue

        # Granting unknowns is what lets a partially-checkable rule match at all,
        # so also require that the APIs are load-bearing: the same rule must fail
        # when no API is present. Otherwise it rode in purely on unknowns.
        if not evaluate(program, present_ids, unknown_is_true=True):
            continue
        if evaluate(program, set(), unknown_is_true=True):
            continue

        rule_apis = _rule_apis(conn, rule_id)
        matched = [api for api in rule_apis if api in present_norm]
        if not matched:
            continue

        results.append(
            Capability(
                name=name,
                namespace=namespace,
                description=description,
                confidence=confidence,
                attck=json.loads(attck) if attck else [],
                mbc=json.loads(mbc) if mbc else [],
                matched_apis=matched,
                missing_apis=[a for a in rule_apis if a not in present_norm],
                unknown_leaves=unknown,
            )
        )

    results.sort(key=lambda c: (c.confidence != CONFIDENCE_HIGH, -c.score, c.name))
    return results


def rules_for_api(
    conn: sqlite3.Connection, api_name: str, present: set[str] | None = None
) -> list[RuleForApi]:
    """Combinations the given API takes part in, richest first.

    ``present`` is the target's API set, used only to mark which parts of each
    combination are already there. Omit it to describe the combination in the
    abstract, which is what the panel shows before a target is loaded.
    """
    key = canonical(api_name)
    present_norm = {canonical(n) for n in present} if present else set()

    results: list[RuleForApi] = []
    for row in conn.execute(
        "SELECT r.id, r.name, r.namespace, r.attck_json, r.mbc_json, r.unknown_leaves"
        " FROM capa_rule r"
        " JOIN capa_rule_api ra ON ra.rule_id = r.id"
        " JOIN capa_api ca ON ca.id = ra.capa_api_id"
        " WHERE ca.name_norm = ? AND r.is_lib = 0",
        (key,),
    ).fetchall():
        rule_id, name, namespace, attck, mbc, unknown = row
        rule_apis = _rule_apis(conn, rule_id)
        results.append(
            RuleForApi(
                name=name,
                namespace=namespace,
                attck=json.loads(attck) if attck else [],
                mbc=json.loads(mbc) if mbc else [],
                present_apis=[a for a in rule_apis if a in present_norm or a == key],
                absent_apis=[
                    a for a in rule_apis if a not in present_norm and a != key
                ],
                confidence=CONFIDENCE_HIGH if unknown == 0 else CONFIDENCE_PARTIAL,
                unknown_leaves=unknown,
            )
        )

    results.sort(key=lambda r: (-r.completeness, len(r.absent_apis), r.name))
    return results


def imports_from_pe(path: Path) -> set[str]:
    """Read a PE's import table without any third-party dependency.

    The plugin reads the same directory out of debuggee memory instead, which
    also catches manually mapped modules; this is the offline equivalent for
    testing the matcher against a real binary.
    """
    import struct

    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{path}: not a PE file")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path}: bad PE signature")

    coff = pe_offset + 4
    num_sections, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from("<H", data, opt)
    is_pe32_plus = magic == 0x20B

    # Import directory is data directory index 1.
    dir_offset = opt + (112 if is_pe32_plus else 96)
    import_rva, import_size = struct.unpack_from("<II", data, dir_offset + 8)
    if not import_rva:
        return set()

    sections = []
    section_table = opt + opt_size
    for i in range(num_sections):
        entry = section_table + i * 40
        virtual_addr, = struct.unpack_from("<I", data, entry + 12)
        raw_size, = struct.unpack_from("<I", data, entry + 16)
        raw_ptr, = struct.unpack_from("<I", data, entry + 20)
        virtual_size, = struct.unpack_from("<I", data, entry + 8)
        sections.append((virtual_addr, max(raw_size, virtual_size), raw_ptr, raw_size))

    def to_offset(rva: int) -> int | None:
        for virtual_addr, span, raw_ptr, raw_size in sections:
            if virtual_addr <= rva < virtual_addr + span:
                delta = rva - virtual_addr
                return raw_ptr + delta if delta < raw_size else None
        return None

    def read_cstring(offset: int) -> str:
        end = data.index(b"\0", offset)
        return data[offset:end].decode("ascii", "replace")

    names: set[str] = set()
    descriptor = to_offset(import_rva)
    if descriptor is None:
        return names

    while True:
        fields = struct.unpack_from("<IIIII", data, descriptor)
        original_first_thunk, _, _, name_rva, first_thunk = fields
        if not any(fields):
            break

        thunk_rva = original_first_thunk or first_thunk
        thunk = to_offset(thunk_rva) if thunk_rva else None
        if thunk is not None:
            entry_size = 8 if is_pe32_plus else 4
            ordinal_flag = 1 << (63 if is_pe32_plus else 31)
            while True:
                fmt = "<Q" if is_pe32_plus else "<I"
                value, = struct.unpack_from(fmt, data, thunk)
                if not value:
                    break
                if not value & ordinal_flag:
                    hint = to_offset(value)
                    if hint is not None:
                        names.add(read_cstring(hint + 2))
                thunk += entry_size

        descriptor += 20

    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apis", nargs="*", help="API names present in the target")
    parser.add_argument("--pe", type=Path, help="read the API set from a PE's imports")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument(
        "--high-confidence",
        action="store_true",
        help="only rules decided entirely by APIs",
    )
    parser.add_argument(
        "--for-api",
        metavar="NAME",
        help="show the combinations this API takes part in instead",
    )
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if not args.db.exists():
        print(f"index not found: {args.db}", file=sys.stderr)
        return 2

    api_names = set(args.apis)
    if args.pe:
        api_names |= imports_from_pe(args.pe)
    if not api_names and not args.for_api:
        parser.error("provide API names, --pe, or --for-api")

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        if args.for_api:
            return _report_for_api(conn, args, api_names)
        return _report_capabilities(conn, args, api_names)
    finally:
        conn.close()


def _report_for_api(
    conn: sqlite3.Connection, args: argparse.Namespace, present: set[str]
) -> int:
    rules = rules_for_api(conn, args.for_api, present)
    if args.high_confidence:
        rules = [r for r in rules if r.confidence == CONFIDENCE_HIGH]
    if not rules:
        print(f"no capa rule references {args.for_api}")
        return 1

    scope = f" (against {len(present)} known APIs)" if present else ""
    print(f"{args.for_api}: {len(rules)} combinations{scope}\n")
    for rule in rules[: args.limit]:
        flag = "" if rule.confidence == CONFIDENCE_HIGH else "  ~"
        print(f"{rule.name}  [{rule.namespace or '-'}]{flag}")
        for technique in rule.attck:
            print(f"      ATT&CK: {technique['text']} {technique['id']}")
        if rule.present_apis:
            print(f"      present: {', '.join(rule.present_apis)}")
        if rule.absent_apis:
            shown = rule.absent_apis[:8]
            more = f" (+{len(rule.absent_apis) - 8})" if len(rule.absent_apis) > 8 else ""
            print(f"      absent:  {', '.join(shown)}{more}")
        if rule.unknown_leaves:
            print(f"      note: capa also checks {rule.unknown_leaves} "
                  "non-API feature(s) not visible in the import table")
    if len(rules) > args.limit:
        print(f"\n... {len(rules) - args.limit} more")
    return 0


def _report_capabilities(
    conn: sqlite3.Connection, args: argparse.Namespace, api_names: set[str]
) -> int:
    minimum = CONFIDENCE_HIGH if args.high_confidence else CONFIDENCE_PARTIAL
    found = match(conn, api_names, min_confidence=minimum)
    high = [c for c in found if c.confidence == CONFIDENCE_HIGH]

    print(f"{len(api_names)} APIs -> {len(found)} capabilities "
          f"({len(high)} decided by APIs alone)\n")
    for capability in found[: args.limit]:
        flag = "" if capability.confidence == CONFIDENCE_HIGH else "  ~"
        print(f"{capability.name}  [{capability.namespace or '-'}]{flag}")
        for technique in capability.attck:
            print(f"      ATT&CK: {technique['text']} {technique['id']}")
        print(f"      matched: {', '.join(capability.matched_apis)}")
        if capability.unknown_leaves:
            print(f"      note: capa also checks {capability.unknown_leaves} "
                  "non-API feature(s) not visible in the import table")
    if len(found) > args.limit:
        print(f"\n... {len(found) - args.limit} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
