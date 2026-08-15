#!/usr/bin/env python3
"""Build the APISignature index.

Runs offline on a maintainer's machine and emits a single SQLite file that the
C++ plugin reads at runtime. Nothing in here ships to an analyst.

    python etl/build_index.py --out dist/apisignature.db

Sources are layered, most authoritative last, so a later source repairs earlier
gaps rather than duplicating rows:

    malapi.json   the malicious-intent layer, plus fallback docs for the
                  natives Microsoft does not document
    sdk-api       Microsoft's own reference, which supplies the full parameter
                  and return-value prose MalAPI's scrape truncated
    capa-rules    the API-combination layer
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ETL_DIR = Path(__file__).resolve().parent
REPO_ROOT = ETL_DIR.parent
sys.path.insert(0, str(ETL_DIR))

import capabilities  # noqa: E402
from normalize import canonical  # noqa: E402
from records import ApiDoc, MalApiInfo  # noqa: E402
from sources import capa as capa_source  # noqa: E402
from sources import malapi as malapi_source  # noqa: E402
from sources import sdk_api  # noqa: E402
import textstore  # noqa: E402

SCHEMA_VERSION = "3"

#: Reproduced in the panel's About section. We redistribute a prebuilt index, so
#: attribution travels with the data rather than living only in the README.
ATTRIBUTION = {
    "attribution.malapi": (
        "API abuse descriptions and attack categories from malapi.io, "
        "curated by mr.d0x and contributors."
    ),
    "attribution.capa": (
        "API combination rules from mandiant/capa-rules, Apache License 2.0."
    ),
    # Verified against vendor/sdk-api/LICENSE: Creative Commons Attribution 4.0
    # International. We redistribute a prebuilt index rather than asking each
    # user to clone the source, so the attribution has to travel with the data.
    "attribution.microsoft": (
        "Windows API reference documentation (c) Microsoft Corporation, from "
        "MicrosoftDocs/sdk-api and MicrosoftDocs/windows-driver-docs-ddi, "
        "licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). "
        "Documentation text is unmodified apart from rendering to HTML."
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--malapi",
        type=Path,
        default=REPO_ROOT / "malapi.json",
        help="path to malapi.json (default: repo root)",
    )
    parser.add_argument(
        "--capa-rules",
        type=Path,
        default=REPO_ROOT / "vendor" / "capa-rules",
        help="path to a capa-rules checkout (default: vendor/capa-rules)",
    )
    parser.add_argument(
        "--sdk-api",
        type=Path,
        nargs="?",
        const=REPO_ROOT / "vendor",
        default=REPO_ROOT / "vendor",
        help="directory holding sdk-api and/or windows-driver-docs-ddi checkouts",
    )
    parser.add_argument(
        "--no-sdk-api",
        dest="sdk_api",
        action="store_const",
        const=None,
        help="skip the Microsoft corpus and build a MalAPI-only index",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="stop after N corpus documents (for quick iteration)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "dist" / "apisignature.db",
        help="output index path (default: dist/apisignature.db)",
    )
    args = parser.parse_args(argv)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.out.exists():
        args.out.unlink()

    print(f"[*] building {args.out}")
    conn = sqlite3.connect(args.out)
    try:
        conn.executescript((ETL_DIR / "schema.sql").read_text(encoding="utf-8"))

        print(f"[*] loading {args.malapi}")
        docs, infos = malapi_source.load(args.malapi)
        print(f"    {len(docs)} entries")

        # Document text is interned and written at the end: the dictionary has to
        # be built from the corpus, which is streamed rather than held in memory.
        # See etl/textstore.py.
        interner = textstore.Interner()

        api_ids = _insert_docs(conn, docs, interner)
        _insert_malapi(conn, infos, api_ids)
        _insert_fts(conn, docs, infos, api_ids)

        if args.sdk_api:
            for root, source in _corpus_roots(args.sdk_api):
                print(f"[*] loading {source} from {root}")
                merged, added = _merge_corpus(
                    conn, root, source, api_ids, args.limit, interner
                )
                print(f"    {added} new APIs, {merged} MalAPI entries enriched")

        rows, dict_size = interner.flush(conn, _referenced_text_ids(conn))
        print(f"[*] text: {rows} distinct strings, {dict_size / 1024:.0f}K dictionary")

        rule_count = 0
        if args.capa_rules.is_dir():
            print(f"[*] loading {args.capa_rules}")
            rules = capa_source.load(args.capa_rules)
            rule_count = _insert_capa(conn, rules)
            print(f"    {rule_count} rules")
        else:
            print(f"[!] skipping capa rules: {args.capa_rules} not found")
            print("    git clone --depth 1 https://github.com/mandiant/capa-rules.git"
                  " vendor/capa-rules")

        _insert_meta(conn, args)
        conn.commit()

        # A --limit run only sees an alphabetical slice of the corpus, so the
        # merge-dependent assertions cannot hold and would report spurious
        # failures.
        ok = verify(
            conn, expect_capa=rule_count > 0, full_corpus=not args.limit
        )
    finally:
        conn.close()

    if not ok:
        print("[!] verification failed", file=sys.stderr)
        return 1

    size_mb = args.out.stat().st_size / (1024 * 1024)
    print(f"[+] wrote {args.out} ({size_mb:.1f} MB)")
    return 0


def _truncated_text_ids(conn: sqlite3.Connection) -> list[int]:
    """Interned strings that end mid-sentence, as MalAPI's scrape left them."""
    dictionary = textstore.load_dictionary(conn)
    return [
        text_id
        for text_id, blob in conn.execute("SELECT id, data FROM text")
        if textstore.decompress(bytes(blob), dictionary).endswith("…</p>")
    ]


def _id_list(ids: list[int]) -> str:
    """Inline a list of integers into SQL.

    Safe by construction -- these are ids read back out of the database, never
    user input -- and it keeps the callers readable where a parameter list would
    need building at every call site.
    """
    return ",".join(str(int(value)) for value in ids) or "NULL"


def _referenced_text_ids(conn: sqlite3.Connection) -> list[int]:
    """Every text id something still points at, once enrichment has settled."""
    return [
        row[0]
        for row in conn.execute(
            "SELECT doc_id FROM api WHERE doc_id IS NOT NULL"
            " UNION SELECT return_id FROM api WHERE return_id IS NOT NULL"
            " UNION SELECT desc_id FROM api_param WHERE desc_id IS NOT NULL"
        )
    ]


def _insert_docs(
    conn: sqlite3.Connection, docs: list[ApiDoc], interner: textstore.Interner
) -> dict[str, int]:
    """Insert API documentation rows, returning a name -> id map."""
    api_ids: dict[str, int] = {}
    for doc in docs:
        cursor = conn.execute(
            "INSERT INTO api (name, name_norm, dll, header, syntax, doc_id,"
            "                 return_id, doc_url, source)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                doc.name,
                canonical(doc.name),
                doc.dll,
                doc.header,
                doc.syntax,
                interner.intern(doc.doc_html),
                interner.intern(doc.return_html),
                doc.doc_url,
                doc.source,
            ),
        )
        api_id = int(cursor.lastrowid)
        api_ids[doc.name] = api_id
        _insert_params(conn, api_id, doc.params, interner)
    return api_ids


def _insert_malapi(
    conn: sqlite3.Connection, infos: list[MalApiInfo], api_ids: dict[str, int]
) -> None:
    attack_ids: dict[str, int] = {}
    for name in malapi_source.KNOWN_ATTACKS:
        cursor = conn.execute("INSERT INTO attack (name) VALUES (?)", (name,))
        attack_ids[name] = int(cursor.lastrowid)

    for info in infos:
        api_id = api_ids[info.name]
        conn.execute(
            "INSERT INTO malapi (api_id, description, credits, created,"
            "                    last_update, source_url)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                api_id,
                info.description,
                info.credits,
                info.created,
                info.last_update,
                info.source_url,
            ),
        )
        conn.executemany(
            "INSERT INTO api_attack (api_id, attack_id) VALUES (?, ?)",
            [(api_id, attack_ids[attack]) for attack in info.attacks],
        )


def _insert_fts(
    conn: sqlite3.Connection,
    docs: list[ApiDoc],
    infos: list[MalApiInfo],
    api_ids: dict[str, int],
) -> None:
    """Populate the search index, keyed by api.id so hits map straight to a row."""
    descriptions = {info.name: info.description for info in infos}
    conn.executemany(
        "INSERT INTO api_fts (rowid, name, description) VALUES (?, ?, ?)",
        [
            (api_ids[doc.name], doc.name, descriptions.get(doc.name, ""))
            for doc in docs
        ],
    )


def _corpus_roots(vendor: Path) -> list[tuple[Path, str]]:
    """Locate the content directories of whichever Microsoft repos are present."""
    candidates = [
        (vendor / "sdk-api" / "sdk-api-src" / "content", "sdk-api"),
        (vendor / "windows-driver-docs-ddi" / "wdk-ddi-src" / "content", "driver-ddi"),
    ]
    return [(root, source) for root, source in candidates if root.is_dir()]


def _merge_corpus(
    conn: sqlite3.Connection,
    root: Path,
    source: str,
    api_ids: dict[str, int],
    limit: int | None,
    interner: textstore.Interner,
) -> tuple[int, int]:
    """Layer Microsoft's reference documentation over the MalAPI rows.

    For an API MalAPI already covers, Microsoft's prose replaces the scraped
    description, parameters and return value -- that is what repairs the 191
    truncated parameter descriptions and 62 truncated return values -- while
    MalAPI keeps ``syntax``, because the markdown carries no C signatures.

    Everything else is inserted fresh, taking coverage from 369 APIs to the whole
    documented Win32 surface.
    """
    # MalAPI rows indexed by canonical key, so a casing difference does not stop
    # the merge. MalAPI title-cases the Winsock family (Socket, Accept, Recv)
    # where the real exports and Microsoft's pages are lowercase, and writes
    # GetKeynameTextA for Microsoft's GetKeyNameTextA. Matching on exact name
    # alone left those entries stuck with their truncated scrape.
    malapi_by_canonical: dict[str, int] = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT a.name_norm, a.id FROM api a"
            " JOIN malapi m ON m.api_id = a.id"
        )
    }
    enriched_by_fold: set[int] = set()

    merged = added = 0
    for doc in sdk_api.load(root, source=source, limit=limit):
        existing = api_ids.get(doc.name)

        # Enrich the case-mismatched MalAPI row too, in addition to whatever we
        # do with this document's own spelling below.
        if existing is None:
            folded = malapi_by_canonical.get(canonical(doc.name))
            if folded is not None and folded not in enriched_by_fold:
                enriched_by_fold.add(folded)
                _enrich(conn, folded, doc, interner)
                merged += 1

        if existing is not None:
            _enrich(conn, existing, doc, interner)
            merged += 1
            continue

        cursor = conn.execute(
            "INSERT OR IGNORE INTO api (name, name_norm, dll, header, syntax,"
            "                           doc_id, return_id, doc_url, source)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (doc.name, canonical(doc.name), doc.dll, doc.header, doc.syntax,
             interner.intern(doc.doc_html), interner.intern(doc.return_html),
             doc.doc_url, doc.source),
        )
        if not cursor.rowcount:
            # Two documents describing the same api_name; first one wins.
            continue

        api_id = int(cursor.lastrowid)
        api_ids[doc.name] = api_id
        _insert_params(conn, api_id, doc.params, interner)
        conn.execute(
            "INSERT INTO api_fts (rowid, name, description) VALUES (?, ?, ?)",
            (api_id, doc.name, _plain_text(doc.doc_html)),
        )
        added += 1

    return merged, added


def _enrich(
    conn: sqlite3.Connection, api_id: int, doc, interner: textstore.Interner
) -> None:
    """Overlay Microsoft's prose onto an existing row, keeping MalAPI's syntax."""
    conn.execute(
        "UPDATE api SET doc_id = ?, return_id = ?,"
        "               header = COALESCE(?, header),"
        "               dll = COALESCE(?, dll),"
        "               doc_url = COALESCE(?, doc_url)"
        " WHERE id = ?",
        (interner.intern(doc.doc_html), interner.intern(doc.return_html),
         doc.header, doc.dll, doc.doc_url, api_id),
    )
    # Microsoft's parameter list is complete and correctly ordered, so it
    # replaces the scrape wholesale rather than being merged into it.
    if doc.params:
        conn.execute("DELETE FROM api_param WHERE api_id = ?", (api_id,))
        _insert_params(conn, api_id, doc.params, interner)


def _insert_params(
    conn: sqlite3.Connection, api_id: int, params: list, interner: textstore.Interner
) -> None:
    conn.executemany(
        "INSERT INTO api_param (api_id, ord, name, desc_id) VALUES (?, ?, ?, ?)",
        [
            (api_id, ordinal, p.name, interner.intern(p.desc_html))
            for ordinal, p in enumerate(params)
        ],
    )


def _plain_text(html: str | None) -> str:
    """Strip tags for the search index, which should not match on markup."""
    if not html:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()[:2000]


def classify_evidence(api_leaves: int, unknown_leaves: int) -> str:
    """What kind of evidence can decide a rule. Shared with etl/migrate_v3.py."""
    if api_leaves == 0:
        return "no-api"
    return "api-only" if unknown_leaves == 0 else "mixed"


def _insert_capa(conn: sqlite3.Connection, rules: list) -> int:
    """Insert capa rules, their API dictionary and the reverse index."""
    # Build the API dictionary first so every program can reference ids.
    capa_api_ids: dict[str, int] = {}
    for name in sorted({api for rule in rules for api in rule.apis}):
        cursor = conn.execute("INSERT INTO capa_api (name_norm) VALUES (?)", (name,))
        capa_api_ids[name] = int(cursor.lastrowid)

    for rule in rules:
        program = capa_source.emit_program(rule.tree, capa_api_ids)
        api_leaves, unknown_leaves = rule.leaf_counts()

        # Both are fixed properties of the rule, settled here instead of being
        # rediscovered on every lookup. fires_empty is what stops a rule being
        # reported when its APIs are not load-bearing -- see the schema comment.
        fires_empty = capa_source.evaluate(program, set(), unknown_is_true=True)
        evidence = classify_evidence(api_leaves, unknown_leaves)

        cursor = conn.execute(
            "INSERT INTO capa_rule (name, namespace, description, attck_json,"
            "                       mbc_json, scope_static, scope_dynamic, program,"
            "                       api_count, api_leaves, unknown_leaves, is_lib,"
            "                       fires_empty, evidence, refs_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rule.name,
                rule.namespace,
                rule.description,
                capa_source.to_json(rule.attck),
                capa_source.to_json(rule.mbc),
                rule.scope_static,
                rule.scope_dynamic,
                program,
                len(rule.apis),
                api_leaves,
                unknown_leaves,
                int(rule.is_lib),
                int(fires_empty),
                evidence,
                capa_source.to_json(rule.references),
            ),
        )
        rule_id = int(cursor.lastrowid)
        conn.executemany(
            "INSERT INTO capa_rule_api (rule_id, capa_api_id) VALUES (?, ?)",
            [(rule_id, capa_api_ids[api]) for api in rule.apis],
        )

    return len(rules)


def _insert_meta(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    meta = {
        "schema_version": SCHEMA_VERSION,
        "built_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source.malapi": str(args.malapi.name),
        **ATTRIBUTION,
    }
    conn.executemany(
        "INSERT INTO meta (key, value) VALUES (?, ?)", sorted(meta.items())
    )


def verify(
    conn: sqlite3.Connection, expect_capa: bool = False, full_corpus: bool = True
) -> bool:
    """Assert the properties the panel depends on. Prints a report."""
    print("[*] verifying")
    failures: list[str] = []

    def check(label: str, actual, expected) -> None:
        ok = actual == expected
        print(f"    {'ok  ' if ok else 'FAIL'} {label}: {actual}")
        if not ok:
            failures.append(f"{label}: expected {expected}, got {actual}")

    scalar = lambda sql, *p: conn.execute(sql, p).fetchone()[0]  # noqa: E731

    check("malapi rows", scalar("SELECT COUNT(*) FROM malapi"), 369)
    print(f"    note api rows: {scalar('SELECT COUNT(*) FROM api')}")
    for source, count in conn.execute(
        "SELECT source, COUNT(*) FROM api GROUP BY source ORDER BY 2 DESC"
    ):
        print(f"         {source}: {count}")
    check("attack categories", scalar("SELECT COUNT(*) FROM attack"), 8)
    check(
        "fts rows match api rows",
        scalar("SELECT COUNT(*) FROM api_fts"),
        scalar("SELECT COUNT(*) FROM api"),
    )
    check(
        "MalAPI entries with no attack tag",
        scalar(
            "SELECT COUNT(*) FROM malapi m"
            " WHERE m.api_id NOT IN (SELECT api_id FROM api_attack)"
        ),
        0,
    )
    check(
        "entries with an empty description",
        scalar("SELECT COUNT(*) FROM malapi WHERE TRIM(description) = ''"),
        0,
    )

    # Once both charset spellings are present, sharing a canonical key is
    # expected -- CreateProcessA and CreateProcessW are meant to fold together.
    # What matters is that exact names stay unique, so the exact-first lookup is
    # always deterministic.
    check(
        "duplicate exact names",
        scalar(
            "SELECT COUNT(*) FROM (SELECT name FROM api GROUP BY name HAVING COUNT(*) > 1)"
        ),
        0,
    )
    shared = scalar(
        "SELECT COUNT(*) FROM (SELECT name_norm FROM api GROUP BY name_norm"
        " HAVING COUNT(*) > 1)"
    )
    print(f"    note canonical keys shared by charset variants: {shared}")

    # The intent layer must survive the merge. Once sdk-api contributes its own
    # CreateProcessW row, an id-keyed intent lookup would return nothing for the
    # spelling analysts actually see, so intent is joined on name_norm.
    #
    # Gated on the corpus having actually contributed rows, not merely on the
    # absence of --limit: MalAPI has no W spellings at all, so a --no-sdk-api
    # build has nothing for this to find and would report a failure that means
    # nothing.
    if full_corpus and scalar("SELECT COUNT(*) FROM api WHERE source != 'malapi'"):
        check(
            "MalAPI intent reachable from the W spelling",
            scalar(
                "SELECT COUNT(*) FROM api w JOIN api a ON a.name_norm = w.name_norm"
                " JOIN malapi m ON m.api_id = a.id WHERE w.name = 'CreateProcessW'"
            )
            > 0,
            True,
        )

    # Spot-checks named in the plan: two entries with no Microsoft page at all.
    for name in ("NtCreateThreadEx", "RtlMoveMemory"):
        row = conn.execute(
            "SELECT m.description FROM api a JOIN malapi m ON m.api_id = a.id"
            " WHERE a.name = ?",
            (name,),
        ).fetchone()
        check(f"{name} renders", bool(row and row[0]), True)

    # Truncation carried over from the scrape. Expected to be non-zero until the
    # sdk-api merge lands, so this reports rather than fails.
    #
    # SQL LIKE cannot see inside a compressed blob, so the text is decompressed
    # first. Keeping the check end-to-end matters more than keeping it in SQL:
    # it asserts what the panel will actually render rather than trusting the
    # `truncated` flags the loaders set.
    truncated = _id_list(_truncated_text_ids(conn))
    truncated_params = scalar(
        f"SELECT COUNT(*) FROM api_param WHERE desc_id IN ({truncated})"
    )
    truncated_returns = scalar(
        f"SELECT COUNT(*) FROM api WHERE return_id IN ({truncated})"
    )
    print(f"    note truncated parameter descriptions: {truncated_params}")
    print(f"    note truncated return values: {truncated_returns}")
    if full_corpus and scalar("SELECT COUNT(*) FROM api WHERE source != 'malapi'"):
        # Down from 191 and 62 before the merge. A handful can legitimately
        # survive -- a few natives have no Microsoft page in either repository --
        # so this asserts a ceiling rather than zero, and names whatever is left
        # so a regression shows up as new entries rather than a silent creep.
        check("truncated parameter descriptions at or under ceiling",
              truncated_params <= 4, True)
        check("truncated return values at or under ceiling",
              truncated_returns <= 4, True)
        for (name,) in conn.execute(
            "SELECT DISTINCT a.name FROM api a"
            " LEFT JOIN api_param p ON p.api_id = a.id"
            f" WHERE p.desc_id IN ({truncated}) OR a.return_id IN ({truncated})"
            " ORDER BY a.name"
        ):
            print(f"         still truncated: {name}")
    else:
        print("         (expected to reach 0 once the sdk-api merge lands)")

    if expect_capa:
        _verify_capa(conn, check, scalar)

    for failure in failures:
        print(f"[!] {failure}", file=sys.stderr)
    return not failures


def _verify_capa(conn: sqlite3.Connection, check, scalar) -> None:
    """Assert every feature program is well formed and actually discriminates."""
    check("capa rules", scalar("SELECT COUNT(*) FROM capa_rule") > 0, True)
    check(
        "rules with no program",
        scalar("SELECT COUNT(*) FROM capa_rule WHERE LENGTH(program) = 0"),
        0,
    )

    # Every program must run to completion leaving exactly one value on the
    # stack. A malformed stream would fault inside x64dbg, so it fails here.
    broken: list[str] = []
    api_ids = {
        row[0] for row in conn.execute("SELECT id FROM capa_api")
    }
    for name, program in conn.execute("SELECT name, program FROM capa_rule"):
        try:
            capa_source.evaluate(program, set(), unknown_is_true=False)
            capa_source.evaluate(program, api_ids, unknown_is_true=True)
        except Exception as exc:  # noqa: BLE001 - report any malformed program
            broken.append(f"{name}: {exc}")
    check("malformed programs", len(broken), 0)
    for entry in broken[:5]:
        print(f"         {entry}")

    # A rule satisfiable with no APIs present at all and no unknowns would fire
    # on every target, which means it was flattened wrong.
    always_true = [
        name
        for name, program, unknown_leaves in conn.execute(
            "SELECT name, program, unknown_leaves FROM capa_rule WHERE api_leaves > 0"
        )
        if not unknown_leaves
        and capa_source.evaluate(program, set(), unknown_is_true=False)
    ]
    check("API rules that fire on an empty target", len(always_true), 0)
    for name in always_true[:5]:
        print(f"         {name}")

    high = scalar(
        "SELECT COUNT(*) FROM capa_rule WHERE is_lib = 0 AND api_leaves > 0"
        " AND unknown_leaves = 0"
    )
    partial = scalar(
        "SELECT COUNT(*) FROM capa_rule WHERE is_lib = 0 AND api_leaves > 0"
        " AND unknown_leaves > 0"
    )
    print(f"    note rules decided by APIs alone: {high}")
    print(f"    note rules also needing strings/constants: {partial}")

    # End-to-end discrimination. The matcher is only worth shipping if the
    # classic injection chain surfaces injection and a benign import set does
    # not, so assert both directions rather than just the happy path.
    injector = capabilities.match(
        conn,
        {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
    )
    benign = capabilities.match(
        conn, {"GetCommandLine", "MessageBox", "ExitProcess", "GetStdHandle"}
    )
    injector_names = [c.name for c in injector]
    benign_names = [c.name for c in benign]

    check("injection chain matches 'inject thread'", "inject thread" in injector_names, True)
    check(
        "injection chain ranks an injection rule in the top 3",
        any("inject" in n.lower() for n in injector_names[:3]),
        True,
    )
    check(
        "benign import set matches no injection rule",
        [n for n in benign_names if "inject" in n.lower()],
        [],
    )

    # The high-confidence tier is the one the panel shows by default, so assert
    # it stays clean on a real benign binary rather than trusting the synthetic
    # four-API set above. notepad.exe drops from 152 matches to 19 under this
    # filter, and none of them are alarming.
    notepad = Path(r"C:\Windows\System32\notepad.exe")
    if notepad.exists():
        imports = capabilities.imports_from_pe(notepad)
        strict = capabilities.match(
            conn, imports, min_confidence=capabilities.CONFIDENCE_HIGH
        )
        alarming = [
            c.name
            for c in strict
            if any(
                word in c.name.lower()
                for word in ("inject", "bypass uac", "disable", "ransom", "keylog")
            )
        ]
        check("notepad.exe raises no alarming high-confidence capability", alarming, [])
        print(f"    note notepad.exe -> {len(strict)} high-confidence capabilities")

    # The per-API view is the panel's primary capability display.
    for_api = capabilities.rules_for_api(conn, "VirtualAllocEx")
    check("VirtualAllocEx participates in capa combinations", len(for_api) > 0, True)
    print(f"    note VirtualAllocEx appears in {len(for_api)} combinations")

    print(f"    note injection chain -> {len(injector_names)} capabilities, "
          f"top: {injector_names[:3]}")
    print(f"    note benign set -> {len(benign_names)} capabilities, "
          f"top: {benign_names[:3]}")


if __name__ == "__main__":
    raise SystemExit(main())

