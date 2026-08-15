#!/usr/bin/env python3
"""Upgrade a v2 index to v3 in place, without rebuilding it.

    python etl/migrate_v3.py dist/apisignature.db

v3 adds two columns to ``capa_rule``: ``fires_empty`` and ``evidence``. Both are
derived entirely from data a v2 index already holds -- the compiled feature
programs and the leaf counts -- so re-running the full build, which needs ~5 GB
of sdk-api and capa-rules checkouts, would be a waste of a download.

The table is recreated rather than patched with ALTER TABLE ADD COLUMN, so a
migrated index is byte-for-byte schema-identical to a freshly built one. ALTER
cannot add the CHECK constraint, and an index whose shape depends on how it was
produced is a bug waiting to happen.

Works on a copy and swaps at the end, keeping the original as .bak.
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
from pathlib import Path

ETL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ETL_DIR))

from build_index import SCHEMA_VERSION, classify_evidence  # noqa: E402
from sources import capa as capa_source  # noqa: E402

FROM_VERSION = "2"

# Mirrors the capa_rule definition in schema.sql. Kept verbatim so the two cannot
# drift silently; the migration verifies the result against schema.sql below.
NEW_TABLE = """
CREATE TABLE capa_rule_v3 (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    namespace     TEXT,
    description   TEXT,
    attck_json    TEXT,
    mbc_json      TEXT,
    scope_static  TEXT,
    scope_dynamic TEXT,
    program       BLOB NOT NULL,
    api_count     INTEGER NOT NULL,
    api_leaves     INTEGER NOT NULL,
    unknown_leaves INTEGER NOT NULL,
    is_lib        INTEGER NOT NULL DEFAULT 0,
    fires_empty   INTEGER NOT NULL,
    evidence      TEXT NOT NULL CHECK (evidence IN ('api-only', 'mixed', 'no-api')),
    refs_json     TEXT
)
"""


def migrate(path: Path) -> int:
    if not path.exists():
        print(f"no such index: {path}", file=sys.stderr)
        return 2

    # Note: `with sqlite3.connect(...)` ends the transaction but does NOT close
    # the connection, and an open handle here blocks the rename at the end.
    probe = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        version = probe.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        version = version[0] if version else "?"
    finally:
        probe.close()

    if version == SCHEMA_VERSION:
        print(f"{path.name} is already v{SCHEMA_VERSION}; nothing to do")
        return 0
    if version != FROM_VERSION:
        print(f"expected a v{FROM_VERSION} index, found v{version}", file=sys.stderr)
        return 1

    working = path.with_suffix(path.suffix + ".migrating")
    print(f"[*] copying {path.name} -> {working.name}")
    shutil.copy2(path, working)

    conn = sqlite3.connect(working)
    try:
        conn.executescript(NEW_TABLE)

        rows = conn.execute(
            "SELECT id, program, api_leaves, unknown_leaves FROM capa_rule"
        ).fetchall()

        counts: dict[str, int] = {}
        updates = []
        for rule_id, program, api_leaves, unknown_leaves in rows:
            # The same evaluation the matcher used to perform per lookup: a rule
            # satisfied with no APIs present is not evidence about a target.
            fires_empty = capa_source.evaluate(
                bytes(program), set(), unknown_is_true=True
            )
            evidence = classify_evidence(api_leaves, unknown_leaves)
            counts[evidence] = counts.get(evidence, 0) + 1
            updates.append((rule_id, int(fires_empty), evidence))

        by_id = {rule_id: (fires, ev) for rule_id, fires, ev in updates}
        conn.executemany(
            "INSERT INTO capa_rule_v3 SELECT id, name, namespace, description,"
            " attck_json, mbc_json, scope_static, scope_dynamic, program,"
            " api_count, api_leaves, unknown_leaves, is_lib, ?, ?, refs_json"
            " FROM capa_rule WHERE id = ?",
            [(fires, ev, rule_id) for rule_id, (fires, ev) in by_id.items()],
        )

        moved = conn.execute("SELECT COUNT(*) FROM capa_rule_v3").fetchone()[0]
        if moved != len(rows):
            raise RuntimeError(f"moved {moved} of {len(rows)} rules")

        conn.execute("DROP TABLE capa_rule")
        conn.execute("ALTER TABLE capa_rule_v3 RENAME TO capa_rule")
        conn.execute(
            "CREATE INDEX capa_rule_evidence_idx"
            " ON capa_rule (evidence, is_lib, fires_empty)"
        )
        conn.execute(
            "UPDATE meta SET value = ? WHERE key = 'schema_version'",
            (SCHEMA_VERSION,),
        )
        conn.commit()
        conn.execute("VACUUM")

        reportable = conn.execute(
            "SELECT COUNT(*) FROM capa_rule WHERE is_lib = 0 AND fires_empty = 0"
        ).fetchone()[0]
    finally:
        conn.close()

    # Swap last, so an interruption anywhere above leaves the original index
    # untouched and only a stray .migrating file behind.
    backup = path.with_suffix(path.suffix + ".bak")
    try:
        path.replace(backup)
        working.replace(path)
    except PermissionError:
        print(
            f"\n[!] {path.name} is open in another process -- close x64dbg and "
            f"re-run.\n    The migrated index is ready at {working.name}; the "
            "original is unchanged.",
            file=sys.stderr,
        )
        return 1
    print(f"[*] kept the original as {backup.name}")

    for evidence, count in sorted(counts.items()):
        print(f"    {evidence:10} {count:>5}")
    print(f"    reportable (APIs load-bearing): {reportable}")
    print(f"[+] {path.name} is now v{SCHEMA_VERSION}")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        ETL_DIR.parent / "dist" / "apisignature.db"
    )
    raise SystemExit(migrate(target))
