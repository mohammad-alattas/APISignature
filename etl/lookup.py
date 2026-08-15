#!/usr/bin/env python3
"""Query the index the way the plugin will.

Serves two purposes: a command-line way to exercise the index without x64dbg, and
the reference for ``src/index.cpp`` -- the SQL here is the SQL the plugin runs.

    python etl/lookup.py kernel32.CreateProcessW
    python etl/lookup.py "qword ptr ds:[<&VirtualAllocEx>]"
    python etl/lookup.py --search "process injection"
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

ETL_DIR = Path(__file__).resolve().parent
REPO_ROOT = ETL_DIR.parent
sys.path.insert(0, str(ETL_DIR))

import textstore  # noqa: E402
from normalize import parse_symbol  # noqa: E402

DEFAULT_DB = REPO_ROOT / "dist" / "apisignature.db"


def resolve(conn: sqlite3.Connection, raw: str) -> sqlite3.Row | None:
    """Resolve a raw x64dbg symbol to an API row.

    Two stages, mirroring the plugin: try every lookup key against the exact
    ``name`` first, then against the folded ``name_norm``. Exact-first is what
    keeps ``CreateProcessA`` landing on the ANSI entry directly instead of
    arriving there through the base name.
    """
    symbol = parse_symbol(raw)
    if not symbol.lookup_keys:
        return None

    # Stage 1: exact, case-preserving spellings, most specific first.
    keys = symbol.lookup_keys
    placeholders = ",".join("?" * len(keys))
    ordering = " ".join(f"WHEN ? THEN {position}" for position in range(len(keys)))
    row = conn.execute(
        f"SELECT * FROM api WHERE name IN ({placeholders})"
        f" ORDER BY CASE name {ordering} ELSE {len(keys)} END LIMIT 1",
        (*keys, *keys),
    ).fetchone()
    if row:
        return row

    # Stage 2: the case-folded key. Prefer a row that carries MalAPI intent --
    # once sdk-api contributes CreateProcessW alongside MalAPI's CreateProcessA,
    # both share a canonical key and only one of them has the write-up.
    return conn.execute(
        "SELECT a.* FROM api a"
        " LEFT JOIN malapi m ON m.api_id = a.id"
        " WHERE a.name_norm = ?"
        " ORDER BY (m.api_id IS NOT NULL) DESC, a.name LIMIT 1",
        (symbol.canonical_key,),
    ).fetchone()


def malapi_intent(
    conn: sqlite3.Connection, row: sqlite3.Row
) -> tuple[sqlite3.Row | None, str | None]:
    """Fetch the malicious-use write-up for an API, following charset variants.

    Joined on ``name_norm`` rather than ``api_id`` on purpose. Once the sdk-api
    corpus lands, ``CreateProcessW`` has its own row with Microsoft's docs, but
    MalAPI only ever wrote up ``CreateProcessA`` -- an id-keyed lookup would show
    the reference documentation and silently drop the intent layer, which is the
    whole point of the tool.

    Returns the intent row and the name it was written against, so the panel can
    disclose when those differ.
    """
    result = conn.execute(
        "SELECT m.*, a.name AS documented_as FROM malapi m"
        " JOIN api a ON a.id = m.api_id"
        " WHERE a.name_norm = ?"
        # Prefer an exact-name hit when one exists, so CreateProcessA shows its
        # own entry rather than a sibling's.
        " ORDER BY (a.name = ?) DESC, a.name LIMIT 1",
        (row["name_norm"], row["name"]),
    ).fetchone()
    if not result:
        return None, None
    return result, result["documented_as"]


def syntax_for(
    conn: sqlite3.Connection, row: sqlite3.Row
) -> tuple[str | None, str | None]:
    """Signature for an API, following charset variants as ``malapi_intent`` does.

    Most rows have no signature of their own: Microsoft generates prototypes from
    win32metadata rather than storing them in the markdown, so only MalAPI's 332
    entries and 894 sdk-api pages carry one. But CreateProcessA has a signature
    and CreateProcessW does not, and they share a canonical key -- so the wide
    spelling can borrow it.

    The two differ (LPCSTR against LPCWSTR), which is exactly why the name it was
    written against is returned alongside: the panel labels a borrowed signature
    rather than presenting it as this function's own.
    """
    if row["syntax"]:
        return row["syntax"], row["name"]

    sibling = conn.execute(
        "SELECT syntax, name FROM api"
        " WHERE name_norm = ? AND syntax IS NOT NULL AND syntax != ''"
        " ORDER BY (name = ?) DESC, name LIMIT 1",
        (row["name_norm"], row["name"]),
    ).fetchone()
    if not sibling:
        return None, None
    return sibling["syntax"], sibling["name"]


def malapi_attacks(conn: sqlite3.Connection, row: sqlite3.Row) -> list[str]:
    """Attack categories for an API, following charset variants as above."""
    return [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT t.name FROM api a"
            " JOIN api_attack aa ON aa.api_id = a.id"
            " JOIN attack t ON t.id = aa.attack_id"
            " WHERE a.name_norm = ? ORDER BY t.name",
            (row["name_norm"],),
        )
    ]


def describe(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    """Render a resolved API as plain text for the terminal."""
    out: list[str] = []
    api_id = row["id"]

    header = row["name"]
    if row["dll"]:
        header = f"{row['dll']}!{row['name']}"
    out.append(header)
    out.append("=" * len(header))

    intent, intent_name = malapi_intent(conn, row)
    attacks = malapi_attacks(conn, row)

    if intent:
        out.append("")
        out.append("MALICIOUS USE")
        out.append(f"  {intent['description']}")
        if intent_name != row["name"]:
            # The MSDN page and the MalAPI entry are different charset variants
            # of the same call. Say so rather than silently attributing one
            # spelling's write-up to the other.
            out.append(f"  (MalAPI documents this as {intent_name})")
    if attacks:
        out.append(f"  Attacks: {', '.join(attacks)}")

    syntax, syntax_name = syntax_for(conn, row)
    if syntax:
        out.append("")
        out.append("SYNTAX")
        if syntax_name != row["name"]:
            out.append(f"  (signature shown is {syntax_name}'s)")
        out.extend(f"  {line}" for line in syntax.splitlines())

    text = textstore.Reader(conn)

    params = conn.execute(
        "SELECT name, desc_id FROM api_param WHERE api_id = ? ORDER BY ord",
        (api_id,),
    ).fetchall()
    if params:
        out.append("")
        out.append("PARAMETERS")
        for param in params:
            out.append(f"  {param['name']}")
            description = text.get(param["desc_id"])
            if description:
                out.append(f"    {_strip_html(description)[:300]}")

    return_html = text.get(row["return_id"])
    if return_html:
        out.append("")
        out.append("RETURN VALUE")
        out.append(f"  {_strip_html(return_html)[:400]}")

    if row["header"] or row["doc_url"]:
        out.append("")
        if row["header"]:
            out.append(f"Header: {row['header']}")
        if row["doc_url"]:
            out.append(f"Docs:   {row['doc_url']}")

    return "\n".join(out)


def prepare_fts_query(query: str) -> str | None:
    """Turn what a user typed into a valid FTS5 expression.

    Two problems to solve. FTS5 matches whole tokens, so a search box that passes
    input through verbatim finds nothing for "keylog" even though thirteen
    entries describe keylogging -- the trailing term needs to become a prefix
    query. And raw input containing quotes or parentheses is an FTS5 syntax
    error, which must not surface as a crash.

    Explicit FTS5 syntax is passed through untouched so power users keep phrase
    and boolean queries.
    """
    query = query.strip()
    if not query:
        return None

    explicit_syntax = any(ch in query for ch in '"*():') or re.search(
        r"\b(AND|OR|NOT|NEAR)\b", query
    )
    if explicit_syntax:
        return query

    tokens = re.findall(r"[A-Za-z0-9_]+", query)
    if not tokens:
        return None

    # Quote every token to neutralise FTS5 metacharacters, then make the last one
    # a prefix so partial words match as the user types.
    quoted = [f'"{token}"' for token in tokens[:-1]]
    quoted.append(f'"{tokens[-1]}"*')
    return " ".join(quoted)


def search(conn: sqlite3.Connection, query: str, limit: int = 20) -> list[sqlite3.Row]:
    expression = prepare_fts_query(query)
    if not expression:
        return []

    sql = (
        "SELECT a.name, a.dll, snippet(api_fts, 1, '', '', '…', 12) AS excerpt"
        " FROM api_fts f JOIN api a ON a.id = f.rowid"
        " WHERE api_fts MATCH ? ORDER BY rank LIMIT ?"
    )
    try:
        return conn.execute(sql, (expression, limit)).fetchall()
    except sqlite3.OperationalError:
        # Malformed explicit syntax: fall back to treating the whole input as a
        # literal phrase rather than reporting an error at the user.
        literal = '"{}"'.format(query.replace('"', ""))
        try:
            return conn.execute(sql, (literal, limit)).fetchall()
        except sqlite3.OperationalError:
            return []


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("symbol", nargs="?", help="symbol as x64dbg would show it")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--search", metavar="QUERY", help="full-text search instead")
    args = parser.parse_args(argv)

    # The index holds UTF-8; the Windows console defaults to cp1252 and would
    # mangle the ellipsis in search snippets.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if not args.db.exists():
        print(f"index not found: {args.db}\nrun: python etl/build_index.py", file=sys.stderr)
        return 2

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        if args.search:
            rows = search(conn, args.search)
            if not rows:
                print("no matches")
                return 1
            for row in rows:
                dll = f"{row['dll']}!" if row["dll"] else ""
                print(f"{dll}{row['name']}\n    {row['excerpt']}")
            return 0

        if not args.symbol:
            parser.error("provide a symbol or --search")

        row = resolve(conn, args.symbol)
        if not row:
            print(f"no index entry for {args.symbol!r}")
            return 1
        print(describe(conn, row))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
