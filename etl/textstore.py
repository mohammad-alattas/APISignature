"""Interned, dictionary-compressed text storage.

The panel's HTML dominates the index: 63 MB of the original 115 MB was three
columns of document text. Two lossless observations shrink that to about 16 MB.

**Most of it repeats.** 108,592 parameter descriptions are only 70,964 distinct
strings; "Reserved; must be zero" and its relatives are stored thousands of times
over. Interning them into one table and referencing by id removes 39 MB before a
single byte is compressed.

**What is left compresses badly on its own.** These are short HTML fragments, and
zlib restarts from an empty window for each one, so it spends most of its output
re-learning the same boilerplate: per-row compression only reaches 55%. Priming
it with a dictionary of the most common fragments takes it to 36%. That single
change is the difference between a 75 MB index and a 46 MB one.

Raw deflate is used (``wbits=-15``) rather than the zlib container: the header
would cost bytes per row for a checksum SQLite already guarantees, and raw
streams let the reader install the dictionary immediately after init instead of
waiting for a ``Z_NEED_DICT`` that never arrives.
"""

from __future__ import annotations

import zlib
from collections.abc import Iterable, Sequence

# zlib's window is 32 KB, so anything longer is ignored from the front. Sized to
# match rather than pretend.
DICTIONARY_SIZE = 32768

_WBITS = -15  # raw deflate, no header or trailer
_LEVEL = 9


def build_dictionary(texts_least_used_first: Iterable[str]) -> bytes:
    """Assemble a dictionary from sample text, hottest material last.

    Order is not cosmetic. zlib keeps only the *tail* of an over-long dictionary,
    and matches nearer the end encode to shorter back-references, so the strings
    that appear most often in the corpus belong at the end.
    """
    joined = "".join(text for text in texts_least_used_first if text)
    return joined.encode("utf-8")[-DICTIONARY_SIZE:]


def compress(text: str, dictionary: bytes) -> bytes:
    compressor = zlib.compressobj(
        _LEVEL, zlib.DEFLATED, _WBITS, 9, zlib.Z_DEFAULT_STRATEGY, zdict=dictionary
    )
    return compressor.compress(text.encode("utf-8")) + compressor.flush()


def decompress(blob: bytes, dictionary: bytes) -> str:
    decompressor = zlib.decompressobj(_WBITS, zdict=dictionary)
    return (decompressor.decompress(blob) + decompressor.flush()).decode("utf-8")


class Interner:
    """Assigns ids to distinct strings, then writes them all in one pass.

    Writing is deferred because the dictionary has to be built from the corpus,
    and the corpus is streamed rather than held in memory -- there is no moment
    early on when a representative sample exists. Buffering the distinct strings
    costs about 40 MB of RAM during the build and buys both a dictionary drawn
    from the real distribution and accurate use counts to order it by.
    """

    def __init__(self) -> None:
        self._ids: dict[str, int] = {}
        self._texts: list[str] = []
        self._uses: list[int] = []

    def intern(self, text: str | None) -> int | None:
        """Return the id for ``text``, assigning one the first time it is seen.

        Empty and missing text share one representation -- NULL -- because the
        panel treats "absent" and "empty" identically, and a row per empty string
        is pure overhead.
        """
        if not text:
            return None

        text_id = self._ids.get(text)
        if text_id is None:
            text_id = len(self._texts) + 1
            self._ids[text] = text_id
            self._texts.append(text)
            self._uses.append(0)

        self._uses[text_id - 1] += 1
        return text_id

    def flush(self, conn, referenced: Sequence[int]) -> tuple[int, int]:
        """Write the referenced strings and the dictionary. Returns (rows, dict size).

        Only referenced ids are written. Enrichment replaces MalAPI's prose with
        Microsoft's, orphaning the strings it displaced; keeping them would store
        text nothing can reach. Ids are left as assigned rather than renumbered,
        since the gaps cost nothing and renumbering would invalidate every
        foreign key already inserted.
        """
        wanted = sorted(set(referenced))

        # Hottest last: see build_dictionary.
        by_use = sorted(wanted, key=lambda text_id: self._uses[text_id - 1])
        dictionary = build_dictionary(self._texts[text_id - 1] for text_id in by_use)

        conn.execute("INSERT INTO text_dict (id, data) VALUES (1, ?)", (dictionary,))
        conn.executemany(
            "INSERT INTO text (id, size, data) VALUES (?, ?, ?)",
            (
                (
                    text_id,
                    # Uncompressed length, so the reader allocates once instead
                    # of growing a buffer until inflate stops asking for room.
                    len(self._texts[text_id - 1].encode("utf-8")),
                    compress(self._texts[text_id - 1], dictionary),
                )
                for text_id in wanted
            ),
        )
        return len(wanted), len(dictionary)

    @property
    def distinct(self) -> int:
        return len(self._texts)


def load_dictionary(conn) -> bytes:
    row = conn.execute("SELECT data FROM text_dict WHERE id = 1").fetchone()
    return bytes(row[0]) if row else b""


class Reader:
    """Reads interned text back. The reference for ``src/index.cpp``."""

    def __init__(self, conn) -> None:
        self._conn = conn
        self._dictionary = load_dictionary(conn)

    def get(self, text_id: int | None) -> str | None:
        if text_id is None:
            return None
        row = self._conn.execute(
            "SELECT data FROM text WHERE id = ?", (text_id,)
        ).fetchone()
        if row is None:
            return None
        return decompress(bytes(row[0]), self._dictionary)
