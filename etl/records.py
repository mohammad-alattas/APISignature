"""Shared record types produced by every source loader.

``sources/malapi.py`` and ``sources/sdk_api.py`` both emit these, which is what
lets ``build_index.py`` merge them without knowing where a field came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ApiParam:
    """One parameter of an API, in declaration order."""

    name: str
    desc_html: str | None = None
    #: True when the source text was cut off mid-sentence. MalAPI's scrape
    #: truncates 191 of its 1148 parameter descriptions with a trailing ellipsis;
    #: the sdk-api merge is expected to replace every one of them.
    truncated: bool = False


@dataclass
class ApiDoc:
    """The reference documentation half of an entry."""

    name: str
    source: str
    dll: str | None = None
    header: str | None = None
    syntax: str | None = None
    doc_html: str | None = None
    return_html: str | None = None
    return_truncated: bool = False
    doc_url: str | None = None
    params: list[ApiParam] = field(default_factory=list)

    @property
    def truncated_param_count(self) -> int:
        return sum(1 for p in self.params if p.truncated)


@dataclass
class MalApiInfo:
    """The malicious-intent half of an entry, present only for MalAPI's 369."""

    name: str
    description: str
    attacks: list[str] = field(default_factory=list)
    credits: str | None = None
    created: str | None = None
    last_update: str | None = None
    source_url: str | None = None
