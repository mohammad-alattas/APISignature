"""Loader for malapi.io's scraped dataset.

Supplies the malicious-intent layer -- how each API is abused, and under which
attack categories -- plus a fallback set of reference documentation for the
entries Microsoft does not document (the Nt*/Rtl* natives, mostly).

Known shape of the input, as of the 369-entry snapshot in the repo root:

  * every entry has name, description, library, attacks, created, last_update,
    credits and source_url
  * 332 of 369 carry a complete C signature; the 37 without are natives
  * 191 of 1148 parameter descriptions and 62 of 332 return values are cut off
    mid-sentence with an ellipsis, which the sdk-api merge is expected to repair
"""

from __future__ import annotations

import json
from pathlib import Path

from records import ApiDoc, ApiParam, MalApiInfo
from render import is_truncated, text_to_html

#: MalAPI's own eight attack categories, in the order the site presents them.
#: Declared explicitly so an unexpected ninth category fails loudly rather than
#: silently appearing in the panel.
KNOWN_ATTACKS = (
    "Anti-Debugging",
    "Enumeration",
    "Evasion",
    "Helper",
    "Injection",
    "Internet",
    "Ransomware",
    "Spying",
)


def load(path: Path) -> tuple[list[ApiDoc], list[MalApiInfo]]:
    """Load malapi.json into documentation and intent records.

    Returns ``(docs, infos)`` as parallel lists, one entry each per API.
    """
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a JSON array of API entries")

    docs: list[ApiDoc] = []
    infos: list[MalApiInfo] = []
    seen: set[str] = set()

    for entry in entries:
        name = (entry.get("name") or "").strip()
        if not name:
            raise ValueError(f"{path}: entry without a name: {entry!r}")
        if name in seen:
            raise ValueError(f"{path}: duplicate entry for {name}")
        seen.add(name)

        unknown = set(entry.get("attacks") or ()) - set(KNOWN_ATTACKS)
        if unknown:
            raise ValueError(f"{name}: unrecognised attack categories {sorted(unknown)}")

        docs.append(_to_doc(entry, name))
        infos.append(_to_info(entry, name))

    return docs, infos


def _to_doc(entry: dict, name: str) -> ApiDoc:
    return_value = entry.get("return_value")
    return ApiDoc(
        name=name,
        source="malapi",
        # `dll_normalized` is malapi's own lowercased form; `library` is the
        # display spelling. Prefer the normalized one and fall back.
        dll=entry.get("dll_normalized") or entry.get("library") or None,
        header=entry.get("header") or None,
        syntax=entry.get("syntax") or None,
        return_html=text_to_html(return_value),
        return_truncated=is_truncated(return_value),
        # `syntax_url` points at the page the signature was scraped from and is
        # the better link when the two differ; documentation_url is sometimes a
        # third-party page for the undocumented natives.
        doc_url=entry.get("syntax_url") or entry.get("documentation_url") or None,
        params=[
            ApiParam(
                name=(param.get("name") or "").strip(),
                desc_html=text_to_html(param.get("description")),
                truncated=is_truncated(param.get("description")),
            )
            for param in entry.get("parameters") or ()
        ],
    )


def _to_info(entry: dict, name: str) -> MalApiInfo:
    return MalApiInfo(
        name=name,
        description=(entry.get("description") or "").strip(),
        attacks=list(entry.get("attacks") or ()),
        credits=entry.get("credits") or None,
        created=entry.get("created") or None,
        last_update=entry.get("last_update") or None,
        source_url=entry.get("source_url") or None,
    )
