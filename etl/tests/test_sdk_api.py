"""Tests for the Microsoft reference-documentation loader.

Frontmatter parsing is hand-rolled for speed, so it is tested against the real
shapes that appear in the corpus rather than an idealised sample.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ETL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = ETL_DIR.parent
sys.path.insert(0, str(ETL_DIR))

from sources import sdk_api  # noqa: E402

CORPUS = REPO_ROOT / "vendor" / "sdk-api" / "sdk-api-src" / "content"
needs_corpus = pytest.mark.skipif(
    not CORPUS.is_dir(), reason="sdk-api checkout not present"
)

SAMPLE = """\
---
UID: NF:memoryapi.VirtualAllocEx
title: VirtualAllocEx function (memoryapi.h)
description: Reserves, commits, or changes the state of a region of memory.
req.header: memoryapi.h
req.dll: Kernel32.dll
req.lib: onecore.lib
req.irql:
api_location:
 - api-ms-win-core-memory-l1-1-9.dll
 - Kernel32.dll
api_name:
 - VirtualAllocEx
---

# VirtualAllocEx function

## -description

Reserves memory. See <a href="/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc">VirtualAlloc</a>.

## -parameters

### -param hProcess [in]

The handle to a process.

### -param dwSize [in]

The size in bytes.

## -returns

The base address, or <b>NULL</b> on failure.

## -remarks

Not shown in the panel.
"""


# --------------------------------------------------------------------------
# Frontmatter
# --------------------------------------------------------------------------


def test_frontmatter_scalars_and_lists() -> None:
    fields, body = sdk_api.parse_frontmatter(SAMPLE)
    assert fields["UID"] == "NF:memoryapi.VirtualAllocEx"
    assert fields["req.header"] == "memoryapi.h"
    assert fields["req.dll"] == "Kernel32.dll"
    assert fields["api_name"] == ["VirtualAllocEx"]
    assert fields["api_location"] == [
        "api-ms-win-core-memory-l1-1-9.dll",
        "Kernel32.dll",
    ]
    assert body.lstrip().startswith("# VirtualAllocEx function")


def test_frontmatter_empty_value_starts_a_list_not_a_scalar() -> None:
    """`req.irql:` with nothing after it must not swallow the next key."""
    fields, _ = sdk_api.parse_frontmatter(SAMPLE)
    assert fields["req.irql"] == []
    assert fields["api_location"][0].startswith("api-ms-win")


def test_document_without_frontmatter_is_passed_through() -> None:
    fields, body = sdk_api.parse_frontmatter("# Just a heading\n")
    assert fields == {}
    assert body == "# Just a heading\n"


def test_quoted_values_are_unquoted() -> None:
    fields, _ = sdk_api.parse_frontmatter('---\ntitle: "Quoted title"\n---\nbody\n')
    assert fields["title"] == "Quoted title"


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def test_sections_split_on_double_hash_dash() -> None:
    _, body = sdk_api.parse_frontmatter(SAMPLE)
    sections = sdk_api.split_sections(body)
    assert set(sections) >= {"description", "parameters", "returns", "remarks"}
    assert "Reserves memory" in sections["description"]


def test_params_keep_order_and_direction() -> None:
    _, body = sdk_api.parse_frontmatter(SAMPLE)
    params = sdk_api.split_params(sdk_api.split_sections(body)["parameters"])
    assert [p[0] for p in params] == ["hProcess", "dwSize"]
    assert params[0][1] == "in"
    assert "handle to a process" in params[0][2]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_relative_links_are_absolutized() -> None:
    """Site-relative hrefs would be dead links inside the panel."""
    html = sdk_api.to_html('See <a href="/windows/desktop/api/x">X</a>.')
    assert 'href="https://learn.microsoft.com/windows/desktop/api/x"' in html


def test_absolute_links_are_left_alone() -> None:
    html = sdk_api.to_html('<a href="https://example.com/x">X</a>')
    assert html.count("https://") == 1


def test_inline_html_survives_rendering() -> None:
    html = sdk_api.to_html("The value is <b>NULL</b> on failure.")
    assert "<b>NULL</b>" in html


def test_empty_section_renders_as_none() -> None:
    assert sdk_api.to_html("") is None
    assert sdk_api.to_html("   \n  ") is None


# --------------------------------------------------------------------------
# Whole-document parsing
# --------------------------------------------------------------------------


def test_parse_file(tmp_path: Path) -> None:
    # The URL is built from the containing directory, which is the header name.
    # That is not cosmetic: 230 documents live under dotted directories such as
    # "windows.data.pdf.interop" whose filenames hyphenate the same name, so the
    # directory is the only faithful source.
    content = tmp_path / "memoryapi"
    content.mkdir()
    path = content / "nf-memoryapi-virtualallocex.md"
    path.write_text(SAMPLE, encoding="utf-8")

    docs = sdk_api.parse_file(path)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.name == "VirtualAllocEx"
    assert doc.dll == "kernel32"
    assert doc.header == "memoryapi.h"
    assert doc.source == "sdk-api"
    assert [p.name for p in doc.params] == ["hProcess", "dwSize"]
    assert doc.doc_url.endswith("/memoryapi/nf-memoryapi-virtualallocex")
    # Microsoft's markdown carries no C signature; MalAPI remains the source.
    assert doc.syntax is None
    # Nothing from Microsoft is a truncated scrape.
    assert doc.truncated_param_count == 0
    assert doc.return_truncated is False


def test_non_function_documents_are_skipped(tmp_path: Path) -> None:
    """Structures, enums and interfaces have no place in an API panel."""
    path = tmp_path / "nf-fake-struct.md"
    path.write_text(SAMPLE.replace("NF:memoryapi", "NS:memoryapi"), encoding="utf-8")
    assert sdk_api.parse_file(path) == []


def test_name_falls_back_to_the_uid_suffix(tmp_path: Path) -> None:
    path = tmp_path / "nf-x-y.md"
    path.write_text(
        SAMPLE.replace("api_name:\n - VirtualAllocEx\n", ""), encoding="utf-8"
    )
    docs = sdk_api.parse_file(path)
    assert [d.name for d in docs] == ["VirtualAllocEx"]


@needs_corpus
def test_doc_url_uses_the_directory_not_the_filename() -> None:
    """Dotted header directories are hyphenated in the filename."""
    dotted = next(CORPUS.glob("windows.data.pdf.interop/nf-*.md"), None)
    if dotted is None:
        pytest.skip("dotted-header sample not present")
    docs = sdk_api.parse_file(dotted)
    assert docs
    assert "/windows.data.pdf.interop/" in docs[0].doc_url


# --------------------------------------------------------------------------
# Against the real corpus
# --------------------------------------------------------------------------


@needs_corpus
def test_real_document_parses() -> None:
    path = CORPUS / "memoryapi" / "nf-memoryapi-virtualallocex.md"
    docs = sdk_api.parse_file(path)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.name == "VirtualAllocEx"
    assert doc.dll == "kernel32"
    assert [p.name for p in doc.params] == [
        "hProcess",
        "lpAddress",
        "dwSize",
        "flAllocationType",
        "flProtect",
    ]
    assert doc.return_html and "base address" in doc.return_html


@needs_corpus
def test_serial_and_parallel_loading_agree() -> None:
    serial = list(sdk_api.load(CORPUS, limit=60, workers=1))
    parallel = list(sdk_api.load(CORPUS, limit=60))
    assert [d.name for d in serial] == [d.name for d in parallel]
    assert serial and len(serial) == 60


@needs_corpus
def test_one_document_yields_every_declared_spelling() -> None:
    """The regression that broke MalAPI intent for CreateProcessW.

    nf-processthreadsapi-createprocessa.md declares CreateProcess,
    CreateProcessA and CreateProcessW. Emitting only the first left the W
    spelling -- the one that actually appears in a modern disassembly -- with no
    row at all.
    """
    path = CORPUS / "processthreadsapi" / "nf-processthreadsapi-createprocessa.md"
    names = [d.name for d in sdk_api.parse_file(path)]
    assert names == ["CreateProcess", "CreateProcessA", "CreateProcessW"]


def test_interface_qualified_names_keep_the_method(tmp_path: Path) -> None:
    path = tmp_path / "nf-x-y.md"
    path.write_text(
        SAMPLE.replace(" - VirtualAllocEx", " - IFoo::CreateSharedHandle"),
        encoding="utf-8",
    )
    assert [d.name for d in sdk_api.parse_file(path)] == ["CreateSharedHandle"]
