# Third-party notices

This project vendors third-party source code, and the prebuilt index
(`apisignature.db`) redistributes third-party content. Notices for the bundled data
also travel inside the index itself, in its `meta` table, and are shown in the
plugin's **About / attribution** view — the CC BY 4.0 terms require the
attribution to accompany the content, so it has to be present even when the
index is copied away from this repository.

## Bundled data (inside `apisignature.db`)

### Windows API reference documentation

© Microsoft Corporation. Sourced from
[MicrosoftDocs/sdk-api](https://github.com/MicrosoftDocs/sdk-api) and
[MicrosoftDocs/windows-driver-docs-ddi](https://github.com/MicrosoftDocs/windows-driver-docs-ddi),
licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Documentation text is unmodified apart from being rendered from Markdown to
HTML for display.

### API abuse descriptions and attack categories

From [malapi.io](https://malapi.io), curated by mr.d0x and contributors.

This project is not affiliated with or endorsed by malapi.io.

## Vendored source code

### SQLite

[SQLite](https://sqlite.org/) is in the public domain. The amalgamation
(`third_party/sqlite3.c`, `third_party/sqlite3.h`) is included unmodified;
build-time configuration is applied through preprocessor defines in
`CMakeLists.txt` rather than by editing the source.

### zlib

[zlib](https://zlib.net/) by Jean-loup Gailly and Mark Adler, under the zlib
licence — see `third_party/zlib/LICENSE`. Only the inflate side is vendored;
the plugin never compresses.

## Host application

The plugin is built against the [x64dbg](https://x64dbg.com/) plugin SDK.
x64dbg itself is licensed GPLv3 and is not redistributed here.
