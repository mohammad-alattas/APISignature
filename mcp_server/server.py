#!/usr/bin/env python3
"""APISignature as an MCP server.

Exposes the index to any MCP client -- Claude Desktop, Claude Code, Cursor -- so
an assistant can look up Windows APIs against curated data instead of recalling
them from training. Paired with an x64dbg MCP server, the assistant can read the
debuggee *and* consult this index in one conversation.

There is no AI code here and no network access: this reads a local SQLite file
and returns text. The model lives in whatever client connects.

Every query path is the one the plugin itself uses -- ``etl/lookup.py`` and
``etl/capabilities.py`` are imported rather than reimplemented, so the answers an
assistant gets and the answers the panel shows cannot drift apart.

    python mcp_server/server.py            # stdio, for an MCP client to spawn
    APISIGNATURE_DB=path/to.db python mcp_server/server.py
"""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "etl"))

import capabilities  # noqa: E402
import lookup  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

DB_PATH = Path(
    os.environ.get("APISIGNATURE_DB", REPO_ROOT / "dist" / "apisignature.db")
)

mcp = FastMCP("apisignature")


@contextmanager
def _db():
    """A read-only connection per call.

    Per-call rather than shared because SQLite connections are not safe to use
    from multiple threads and an MCP server may dispatch tools concurrently.
    Opening a connection is a file handle, not a parse of the 46 MB index.
    """
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"index not found at {DB_PATH}. Download apisignature.db from the "
            f"releases page, or set APISIGNATURE_DB to its location."
        )
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _fmt_attck(entries: list[dict]) -> str:
    """ATT&CK entries as 'Defense Evasion::Process Injection [T1055]'."""
    out = []
    for entry in entries:
        parts = [entry.get("tactic"), entry.get("technique")]
        label = "::".join(p for p in parts if p)
        if entry.get("id"):
            label = f"{label} [{entry['id']}]" if label else entry["id"]
        if label:
            out.append(label)
    return ", ".join(out)


@mcp.tool()
def lookup_api(symbol: str) -> str:
    """Look up a Windows API function: what it does, and how malware abuses it.

    Accepts whatever a disassembler shows -- "CreateProcessW", "kernel32.dll!
    VirtualAllocEx", "ZwOpenProcess", "__imp_RegSetValueExA". Name folding
    handles A/W variants, Nt/Zw pairs, forwarders and decoration.

    Use this before describing any Windows API to the user: the malicious-use
    layer and attack categories here are curated, and are not reliably known
    from training data.
    """
    with _db() as conn:
        row = lookup.resolve(conn, symbol)
        if row is None:
            return (
                f"No entry for {symbol!r} in the index of 44,527 APIs.\n"
                "It may be an internal function, a non-Windows import, or "
                "misspelled. Do not guess at its behaviour -- say it was not found."
            )

        out = [lookup.describe(conn, row)]

        intent, _ = lookup.malapi_intent(conn, row)
        if intent is None:
            # Said explicitly so the assistant does not fill the gap itself.
            out.append(
                "\nNOTE: this API has no malapi.io entry -- it is not among the "
                "369 APIs catalogued as commonly abused. That is an absence of "
                "curated data, not evidence the call is benign."
            )

        rules = capabilities.rules_for_api(conn, row["name"])
        if rules:
            out.append(f"\nAPI COMBINATIONS ({len(rules)} capa rules mention this)")
            for rule in rules[:8]:
                needs = ", ".join(rule.absent_apis[:6]) or "nothing else"
                out.append(f"  - {rule.name} [{rule.confidence}] also needs: {needs}")
            if len(rules) > 8:
                out.append(f"  ... and {len(rules) - 8} more")

        return "\n".join(out)


@mcp.tool()
def search_apis(query: str, limit: int = 20) -> str:
    """Full-text search across all 44,527 API descriptions.

    Use when you do not have an exact function name -- "process hollowing",
    "keylog", "disable firewall". For a known name, use lookup_api instead.
    """
    with _db() as conn:
        rows = lookup.search(conn, query, limit=max(1, min(limit, 50)))
        if not rows:
            return f"No matches for {query!r}."
        out = [f"{len(rows)} matches for {query!r}:"]
        for row in rows:
            dll = f"{row['dll']}!" if row["dll"] else ""
            out.append(f"  {dll}{row['name']}: {row['excerpt']}")
        return "\n".join(out)


@mcp.tool()
def capa_rules_for_api(api_name: str, present_apis: list[str] | None = None) -> str:
    """Which known malicious API combinations an API takes part in.

    Pass present_apis (for example, a sample's imports) to mark which parts of
    each combination are already there. Rules are from Mandiant's capa-rules.
    """
    with _db() as conn:
        rules = capabilities.rules_for_api(
            conn, api_name, set(present_apis) if present_apis else None
        )
        if not rules:
            return f"No capa rule mentions {api_name!r}."

        out = [f"{len(rules)} combinations involving {api_name}:"]
        for rule in rules[:25]:
            out.append(f"\n{rule.name}  [{rule.confidence} confidence]")
            if rule.namespace:
                out.append(f"  namespace: {rule.namespace}")
            attck = _fmt_attck(rule.attck)
            if attck:
                out.append(f"  ATT&CK: {attck}")
            out.append(f"  present: {', '.join(rule.present_apis) or 'none'}")
            out.append(f"  absent:  {', '.join(rule.absent_apis) or 'none'}")
            if rule.unknown_leaves:
                out.append(
                    f"  NOTE: capa also tests {rule.unknown_leaves} strings or "
                    "constants that an API list cannot show."
                )
        return "\n".join(out)


@mcp.tool()
def analyze_api_set(api_names: list[str], high_confidence_only: bool = True) -> str:
    """Given a set of APIs (a sample's imports), report what it is capable of.

    high_confidence_only=True returns only rules decided entirely by APIs. Keep
    it True unless the user asks for the permissive view: on notepad.exe the
    permissive tier reports 152 capabilities including "bypass UAC", while the
    API-only tier reports 19, all accurate.
    """
    if not api_names:
        return "No APIs given."

    tier = (
        capabilities.CONFIDENCE_HIGH
        if high_confidence_only
        else capabilities.CONFIDENCE_PARTIAL
    )
    with _db() as conn:
        results = capabilities.match(conn, set(api_names), min_confidence=tier)
        if not results:
            return f"No capabilities matched from {len(api_names)} APIs at this tier."

        label = "API-only" if high_confidence_only else "permissive"
        out = [f"{len(results)} capabilities ({label} tier) from {len(api_names)} APIs:"]
        for cap in results[:40]:
            out.append(f"\n{cap.name}  [{cap.confidence}]")
            attck = _fmt_attck(cap.attck)
            if attck:
                out.append(f"  ATT&CK: {attck}")
            out.append(f"  matched: {', '.join(cap.matched_apis)}")
            if cap.missing_apis:
                # Deliberately not called "missing". A capa rule lists every API
                # it recognises, including OR alternatives and optional blocks --
                # createremotethread and pthread_create satisfy the same branch.
                # Calling these missing would have the assistant report that the
                # sample needs all of them, which is false.
                others = ", ".join(cap.missing_apis[:12])
                if len(cap.missing_apis) > 12:
                    others += f", ... (+{len(cap.missing_apis) - 12})"
                out.append(f"  other APIs this rule recognises: {others}")

        out.append(
            "\nIMPORTANT: capa's static scope expects these APIs in the SAME "
            "function. An import list only proves they exist somewhere in the "
            "binary, so this is an over-approximation. Report it as capability, "
            "not as behaviour observed."
        )
        return "\n".join(out)


@mcp.tool()
def list_attack_categories() -> str:
    """The eight malapi.io attack categories and how many APIs each covers."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT t.name, COUNT(*) AS n FROM attack t"
            " JOIN api_attack aa ON aa.attack_id = t.id"
            " GROUP BY t.name ORDER BY n DESC"
        ).fetchall()
        out = ["malapi.io attack categories (369 APIs catalogued in total):"]
        for row in rows:
            out.append(f"  {row['name']}: {row['n']} APIs")
        return "\n".join(out)


@mcp.tool()
def apis_by_attack(category: str, limit: int = 50) -> str:
    """List the APIs in one malapi.io attack category.

    Categories: Helper, Injection, Enumeration, Internet, Evasion, Spying,
    Anti-Debugging, Ransomware.
    """
    with _db() as conn:
        rows = conn.execute(
            "SELECT a.name, a.dll, m.description FROM api a"
            " JOIN api_attack aa ON aa.api_id = a.id"
            " JOIN attack t ON t.id = aa.attack_id"
            " JOIN malapi m ON m.api_id = a.id"
            " WHERE t.name = ? COLLATE NOCASE ORDER BY a.name LIMIT ?",
            (category, max(1, min(limit, 200))),
        ).fetchall()
        if not rows:
            known = ", ".join(
                r[0] for r in conn.execute("SELECT name FROM attack ORDER BY name")
            )
            return f"No category {category!r}. Known categories: {known}"

        out = [f"{len(rows)} APIs in {category}:"]
        for row in rows:
            dll = f"{row['dll']}!" if row["dll"] else ""
            out.append(f"  {dll}{row['name']}: {row['description'][:120]}")
        return "\n".join(out)


@mcp.tool()
def index_info() -> str:
    """Index provenance, coverage and the attribution its licences require."""
    with _db() as conn:
        meta = {
            row["key"]: row["value"] for row in conn.execute("SELECT * FROM meta")
        }
        counts = {
            "APIs": conn.execute("SELECT COUNT(*) FROM api").fetchone()[0],
            "with malicious-use write-ups": conn.execute(
                "SELECT COUNT(*) FROM malapi"
            ).fetchone()[0],
            "capa rules": conn.execute("SELECT COUNT(*) FROM capa_rule").fetchone()[0],
            "with a signature": conn.execute(
                "SELECT COUNT(*) FROM api WHERE syntax IS NOT NULL AND syntax != ''"
            ).fetchone()[0],
        }
        out = [f"Index: {DB_PATH}", f"Built: {meta.get('built_utc', 'unknown')}", ""]
        out += [f"  {label}: {n:,}" for label, n in counts.items()]
        out.append(
            "\nOnly 1,312 of 44,527 APIs carry a signature of their own; "
            "Microsoft does not publish prototypes in the markdown these come "
            "from. A borrowed signature is always labelled."
        )
        out.append("\nATTRIBUTION")
        for key in sorted(k for k in meta if k.startswith("attribution.")):
            out.append(f"  {meta[key]}")
        return "\n".join(out)


if __name__ == "__main__":
    mcp.run()
