"""Loader for Microsoft's own API reference.

Reads the markdown behind learn.microsoft.com from a checkout of
``MicrosoftDocs/sdk-api`` (Win32) or ``MicrosoftDocs/windows-driver-docs-ddi``
(kernel), the same two repositories msdocsviewer uses. A shallow sdk-api clone is
454 MB and carries 46,267 function documents.

This is the layer that repairs MalAPI's scrape: 191 truncated parameter
descriptions and 62 truncated return values come back in full, and coverage
extends from 369 APIs to essentially all of Win32.

**It barely supplies C signatures.** Microsoft generates those on the website
from win32metadata rather than storing them in the markdown: only 894 of 46,267
function pages carry a ``## -syntax`` block. Those are extracted, but most
signatures still come from MalAPI's 332 entries, and a row with neither falls
back to a charset sibling's at query time (see ``lookup.syntax_for``).

Closing the rest of the gap means ingesting
`win32metadata <https://github.com/microsoft/win32metadata>`_, which is MIT
licensed and therefore redistributable inside a prebuilt index. Reading C headers
out of an installed Windows SDK would also work but could not be shipped.

File shape::

    ---
    UID: NF:memoryapi.VirtualAllocEx
    req.header: memoryapi.h
    req.dll: Kernel32.dll
    api_name:
     - VirtualAllocEx
    ---
    # VirtualAllocEx function
    ## -description
    ...
    ## -parameters
    ### -param hProcess [in]
    ...
    ## -returns
    ...

Bodies are markdown with inline HTML (``<b>``, ``<table>``, ``<a href>``), and
links are site-relative, so they are absolutized here rather than left broken in
the panel.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path

from markdown_it import MarkdownIt

from records import ApiDoc, ApiParam

#: Site-relative hrefs become absolute so QTextBrowser can hand them to a browser.
LEARN_BASE = "https://learn.microsoft.com"

_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", re.DOTALL)
_SECTION_RE = re.compile(r"^##\s+-(\w[\w-]*)\s*$", re.MULTILINE)
_PARAM_RE = re.compile(r"^###\s+-param\s+(\S+)\s*(?:\[([^\]]*)\])?\s*$", re.MULTILINE)
_SCALAR_RE = re.compile(r"^([\w.\-]+):[ \t]*(.*)$")
_LIST_ITEM_RE = re.compile(r"^[ \t]*-[ \t]*(.+?)[ \t]*$")
_RELATIVE_HREF_RE = re.compile(r'(href=")(/[^"]*)(")')

#: Only function documents. The repositories also carry structures (NS:),
#: interfaces (NN:), enums (NE:) and callbacks (NC:), which have no place in an
#: API lookup panel.
_FUNCTION_UID_RE = re.compile(r"^N[FC]:", re.IGNORECASE)

#: Guards against api_name entries that are not plain C identifiers.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_markdown = MarkdownIt("commonmark", {"html": True})


def parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    """Split a document into its frontmatter mapping and body.

    Hand-rolled rather than handed to PyYAML: only a handful of fields are
    wanted, the frontmatter is machine-generated and regular, and doing this
    46,000 times makes the difference between a build measured in minutes and one
    measured in tens of minutes.
    """
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text

    header, body = match.group(1), match.group(2)
    fields: dict[str, object] = {}
    current_list: list[str] | None = None

    for line in header.splitlines():
        if not line.strip():
            continue

        if current_list is not None:
            item = _LIST_ITEM_RE.match(line)
            if item and (line.startswith(" ") or line.startswith("\t") or line.startswith("-")):
                current_list.append(_unquote(item.group(1)))
                continue
            current_list = None

        scalar = _SCALAR_RE.match(line)
        if not scalar:
            continue

        key, value = scalar.group(1), scalar.group(2).strip()
        if value:
            fields[key] = _unquote(value)
        else:
            current_list = []
            fields[key] = current_list

    return fields, body


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def extract_syntax(section: str) -> str | None:
    """Pull the C prototype out of a ``## -syntax`` section.

    Only 894 of 46,267 function pages carry one -- Microsoft generates the rest
    on the website from win32metadata rather than storing them in markdown -- but
    894 signatures we would otherwise discard are worth the six lines.

    The body is a fenced code block; the fence is stripped so the panel can style
    it as code rather than re-parse markdown at runtime.
    """
    section = section.strip()
    if not section:
        return None

    lines = section.splitlines()
    if lines and lines[0].lstrip().startswith("```"):
        lines = lines[1:]
        while lines and not lines[-1].lstrip().startswith("```"):
            lines.pop()  # trailing prose after the block, if any
        if lines:
            lines.pop()  # the closing fence

    text = "\n".join(lines).strip()
    return text or None


def split_sections(body: str) -> dict[str, str]:
    """Split a body into its ``## -name`` sections."""
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(body))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections[match.group(1).lower()] = body[match.end() : end].strip()
    return sections


def split_params(section: str) -> list[tuple[str, str, str]]:
    """Split a ``-parameters`` section into ``(name, direction, text)``."""
    params: list[tuple[str, str, str]] = []
    matches = list(_PARAM_RE.finditer(section))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        params.append(
            (
                match.group(1).strip(),
                (match.group(2) or "").strip(),
                section[match.end() : end].strip(),
            )
        )
    return params


def to_html(text: str) -> str | None:
    """Render a section to HTML for QTextBrowser.

    The source is markdown with inline HTML, so HTML passes through and the
    markdown around it is converted. Relative links are absolutized; without that
    every cross-reference in the panel would be dead.
    """
    if not text or not text.strip():
        return None
    html = _markdown.render(text)
    html = _RELATIVE_HREF_RE.sub(rf"\1{LEARN_BASE}\2\3", html)
    return html.strip() or None


def load(
    content_root: Path,
    source: str = "sdk-api",
    limit: int | None = None,
    workers: int | None = None,
) -> Iterator[ApiDoc]:
    """Yield an :class:`ApiDoc` per function document under ``content_root``.

    Streams rather than returning a list: the full corpus does not need to be
    resident at once.

    Rendering markdown is 74% of the work and every file is independent, so the
    corpus is parsed across processes by default -- serially the full sdk-api
    tree takes about 18 minutes. Pass ``workers=1`` to stay in-process, which
    makes profiling and tracebacks legible.
    """
    paths = sorted(content_root.rglob("nf-*.md"))
    if limit:
        paths = paths[: limit * 2]  # allow for non-function files being skipped

    if workers == 1:
        yield from _load_serial(paths, source, limit)
        return

    count = 0
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for docs in pool.map(
            partial(parse_file, source=source), paths, chunksize=64
        ):
            for doc in docs:
                yield doc
                count += 1
                if limit and count >= limit:
                    return


def _load_serial(
    paths: list[Path], source: str, limit: int | None
) -> Iterator[ApiDoc]:
    count = 0
    for path in paths:
        for doc in parse_file(path, source):
            yield doc
            count += 1
            if limit and count >= limit:
                return


def parse_file(path: Path, source: str = "sdk-api") -> list[ApiDoc]:
    """Parse one document into an :class:`ApiDoc` per name it declares.

    Returns a list, not a single doc, because one page routinely documents
    several spellings at once::

        api_name:
         - CreateProcess
         - CreateProcessA
         - CreateProcessW

    Taking only the first would leave ``CreateProcessW`` with no row, so an exact
    lookup on the spelling analysts actually see would miss and the MalAPI intent
    layer would drop out with it. Each name gets its own row sharing the page's
    content; canonical folding still groups them.

    An empty list means the document is not a usable function page.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    fields, body = parse_frontmatter(text)
    uid = str(fields.get("UID") or "")
    if not _FUNCTION_UID_RE.match(uid):
        return []

    names = _pick_names(fields, uid)
    if not names:
        return []

    sections = split_sections(body)
    syntax = extract_syntax(sections.get("syntax", ""))
    doc_html = to_html(sections.get("description", ""))
    return_html = to_html(sections.get("returns", ""))
    dll = _normalize_dll(fields.get("req.dll"))
    header = _first_token(fields.get("req.header"))
    doc_url = _doc_url(path)
    params = [
        ApiParam(
            name=param_name,
            desc_html=to_html(param_text),
            # sdk-api prose is complete; nothing here is a truncated scrape.
            truncated=False,
        )
        for param_name, _direction, param_text in split_params(
            sections.get("parameters", "")
        )
    ]

    return [
        ApiDoc(
            name=name,
            source=source,
            dll=dll,
            header=header,
            syntax=syntax,
            doc_html=doc_html,
            return_html=return_html,
            return_truncated=False,
            doc_url=doc_url,
            params=list(params),
        )
        for name in names
    ]


def _pick_names(fields: dict[str, object], uid: str) -> list[str]:
    """Every function name this document describes, in declaration order."""
    api_name = fields.get("api_name")
    names: list[str] = []

    if isinstance(api_name, list):
        candidates = api_name
    elif isinstance(api_name, str):
        candidates = [api_name]
    else:
        candidates = []

    for candidate in candidates:
        candidate = candidate.strip()
        # Some pages list interface-qualified entries such as
        # "IDisplayDeviceInterop::CreateSharedHandle"; keep the method name.
        if "::" in candidate:
            candidate = candidate.rsplit("::", 1)[-1].strip()
        if candidate and _IDENTIFIER_RE.match(candidate) and candidate not in names:
            names.append(candidate)

    if names:
        return names

    # UID looks like "NF:memoryapi.VirtualAllocEx".
    tail = uid.split(":", 1)[-1].rsplit(".", 1)[-1].strip()
    return [tail] if tail and _IDENTIFIER_RE.match(tail) else []


def _normalize_dll(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    dll = value.split(",")[0].strip()
    for suffix in (".dll", ".sys", ".lib", ".exe"):
        if dll.lower().endswith(suffix):
            dll = dll[: -len(suffix)]
            break
    return dll.lower() or None


def _first_token(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.split(",")[0].strip() or None


def _doc_url(path: Path) -> str | None:
    """Reconstruct the learn.microsoft.com URL from the file's location."""
    stem = path.stem  # nf-memoryapi-virtualallocex
    parent = path.parent.name  # memoryapi
    if not stem.startswith("nf-"):
        return None
    return f"{LEARN_BASE}/windows/win32/api/{parent}/{stem}"
