"""Text-to-HTML rendering for the index.

Everything the panel shows is pre-rendered here at build time so the runtime can
stay parser-free. The target is Qt's rich-text engine, which supports a subset of
HTML 4 -- no flexbox, no custom properties, no ``<details>``. Keep the markup
plain: headings, paragraphs, lists, tables, ``<code>`` and ``<pre>``.
"""

from __future__ import annotations

import html
import re

#: MalAPI's scrape cuts long prose off with a horizontal-ellipsis character.
ELLIPSIS = "…"

_WS_RE = re.compile(r"[ \t]+")
_PARA_SPLIT_RE = re.compile(r"\n\s*\n")


def is_truncated(text: str | None) -> bool:
    """True when scraped prose was cut off mid-sentence."""
    return bool(text) and text.rstrip().endswith(ELLIPSIS)


def escape(text: str) -> str:
    return html.escape(text, quote=False)


def text_to_html(text: str | None) -> str | None:
    """Render plain scraped prose as paragraphs.

    Collapses runs of spaces and tabs but keeps blank-line paragraph breaks, which
    is the only structure MalAPI's plain-text fields carry.
    """
    if not text:
        return None

    paragraphs = []
    for chunk in _PARA_SPLIT_RE.split(text.strip()):
        chunk = _WS_RE.sub(" ", chunk.replace("\n", " ")).strip()
        if chunk:
            paragraphs.append(f"<p>{escape(chunk)}</p>")

    return "\n".join(paragraphs) or None


def code_to_html(code: str | None, language: str = "c") -> str | None:
    """Render a C signature as a preformatted block."""
    if not code:
        return None
    return f'<pre class="lang-{escape(language)}">{escape(code.strip())}</pre>'
