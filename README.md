# APISignature

An x64dbg/x32dbg plugin that answers three questions about the API under your
cursor: **what it does**, **why malware calls it**, and **which known malicious
API combinations it takes part in**.

Select a call in the disassembly and a docked panel fills in — Microsoft's
documentation, malapi.io's malicious-use description and attack categories, and
capability matching against Mandiant's capa rules.

Think [msdocsviewer](https://github.com/alexander-hanel/msdocsviewer) — which is
IDA-only and stops at Microsoft's documentation — plus a malicious-intent layer.

Everything is offline. The plugin is one self-contained DLL and a prebuilt
SQLite index; nothing phones home, and no Python runs on your machine.

## Install

1. **Download** the latest `APISignature-*-win.zip` from the
   [releases page](../../releases).
2. **Close x64dbg**, then extract the archive and run:

   ```powershell
   .\install.ps1
   ```

3. **Start x64dbg.** An `APISignature` tab appears in the main tab bar.

The installer finds x64dbg on its own in most cases. If it doesn't:

```powershell
.\install.ps1 -X64dbgRoot "C:\path\to\x64dbg"
```

<details>
<summary>Installing by hand</summary>

Copy two files into each architecture's plugins directory:

| From the archive | To |
|---|---|
| `APISignature.dp64` + `apisignature.db` | `<x64dbg>\release\x64\plugins\` |
| `APISignature.dp32` + `apisignature.db` | `<x64dbg>\release\x32\plugins\` |

`apisignature.db` must sit **beside** the plugin — that is where the plugin looks for
it. Installing the DLL alone gives you a plugin that loads and then reports
"No index loaded".

</details>

**Requirements:** an x64dbg snapshot from **2025-06-30 or newer**. That release
moved x64dbg to Visual Studio 2022 and Qt 5.12, which is what makes a docked Qt
panel from a plugin possible at all.

## Using it

The panel follows your selection in the disassembly automatically, with a short
debounce so arrowing through a function doesn't fire a lookup per row.

| | |
|---|---|
| **Pin** | Stops the panel following the selection, so you can read while you scroll |
| **Search** | `Ctrl+Shift+A` — full-text search across the whole documentation set |
| **About** | Index location and attribution for the bundled data |

Lookups resolve through labels, branch destinations and IAT entries, so
`call kernel32.VirtualAllocEx` works, and so do forwarded calls that x64dbg
labels as `KERNELBASE.*`.

## Three things worth knowing before trusting the output

**Function signatures are mostly missing, and borrowed ones are labelled.**
Microsoft generates prototypes on the website from win32metadata rather than
storing them in the markdown, so only 894 of 46,267 sdk-api pages carry a
`## -syntax` block. With those plus MalAPI's 332 and 96 from driver-ddi, **1,312
of 44,527 APIs have a signature of their own (2.9%)**; following charset siblings
reaches 1,603 (3.6%). Everything else shows parameters and prose but no
prototype.

A borrowed signature is always labelled — *"signature shown is CreateProcessA's"*
— because the ANSI and wide forms genuinely differ (`LPCSTR` against `LPCWSTR`)
even though the parameter order matches. Closing the rest of the gap means
ingesting [win32metadata](https://github.com/microsoft/win32metadata), which is
the source Microsoft generates those pages from and is MIT licensed, so it can
ship inside a prebuilt index.

**Capability matching is tiered, and the default tier is the narrow one.** capa
rules are precise because they pair APIs with constants — `VirtualAlloc` *and*
`number: 0x40` for PAGE_EXECUTE_READWRITE. An import table has APIs and no
constants. Of 1033 non-library rules, 279 are decided entirely by APIs
(`CONFIDENCE_HIGH`) and 358 also test strings or constants we cannot see
(`CONFIDENCE_PARTIAL`). The difference is not academic: on `notepad.exe` the
permissive tier reports 152 capabilities including *bypass UAC* and *disable
Windows Defender*, while the API-only tier reports 19, all accurate.

Even a high-confidence match is an over-approximation: capa's static scope wants
those APIs in the *same function*, whereas an import set only proves they exist
somewhere in the binary. The panel says so rather than overclaiming.

**Name folding is aggressive, on purpose.** MalAPI lists 122 APIs only under
their `A` spelling while modern binaries call the `W` one; ntdll exports `Nt` and
`Zw` at one address; MalAPI title-cases Winsock (`Socket`) where the real exports
are lowercase (`socket`). Lookup therefore tries exact spellings first and falls
back to a case-folded canonical key. When the entry shown was written against a
different spelling, the panel discloses it — *"MalAPI documents this as
CreateProcessA"* — rather than silently attributing one spelling's write-up to
another.

## Status

| Component | State |
|---|---|
| Name resolver (Python + C++) | Done, 113 Python tests passing |
| Index builder and schema | Done — 44,527 APIs, 1054 capa rules |
| capa capability matching (ETL) | Done, two-tier confidence model |
| CLI tools (`lookup.py`, `capabilities.py`) | Done, usable without x64dbg |
| Plugin, docked panel, auto-follow | Builds and passes tests; not yet confirmed in a live x64dbg session |
| SQLite index reader + panel rendering | Done — verified against the real index |
| capa evaluator **in the panel** | Not started — available via CLI only |

The capability matching that motivates the project currently lives in
`etl/capabilities.py` and has not been ported into the panel yet. Until it is,
the plugin gives you documentation and malicious-use context; the API
combination view is CLI-only.

## Building from source

You only need this if you want to change the plugin. Users should install from
a release.

```powershell
.\build.ps1 -X64dbgRoot "C:\path\to\x64dbg"     # both architectures
.\build.ps1 -Arch x64 -Install                   # and copy into x64dbg\plugins
```

Use the script rather than calling CMake directly — two things about this
toolchain are non-obvious enough to be worth automating.

**Qt must be the exact version x64dbg ships.** `GuiAddQWidgetTab` hands a widget
across the DLL boundary into x64dbg's own Qt, which then calls virtual functions
on it. There is no version negotiation and no error path — a mismatch corrupts
memory rather than failing to link. Verified 5.12.12; confirm yours with
`(Get-Item release\x64\Qt5Core.dll).VersionInfo`. CMake fails the configure step
on a mismatch.

**The newest MSVC cannot compile Qt 5.12.** Toolset 14.51, which VS 2026 installs
by default, removed `stdext::checked_array_iterator`; Qt 5.12 still uses it, and
the failure is pages of template errors from inside `qlist.h` that never name the
cause. Build with **MSVC 14.44 (the v143 toolset)**. Selecting it has a wrinkle:
CMake's VS 2026 generator rejects `-T version=14.44...` under the v145 toolset,
so the tools version has to come from `vcvarsall.bat -vcvars_ver=14.44` and the
generator has to be Ninja. That is all `build.ps1` does. CMake checks for the
extension directly and fails with these instructions rather than letting the
template errors through.

Host-side tests need neither x64dbg nor Qt, so they build with any compiler:

```powershell
cmake -B buildtest -DMALAPI_BUILD_PLUGIN=OFF
cmake --build buildtest
ctest --test-dir buildtest
```

To cut a release archive:

```powershell
.\package.ps1 -X64dbgRoot "C:\path\to\x64dbg"
```

## Rebuilding the index

The released `apisignature.db` is prebuilt, so this is only for changing what goes
into it. The shallow checkouts below come to about 650 MB, and the build takes
roughly six minutes.

```bash
git clone --depth 1 https://github.com/mandiant/capa-rules.git vendor/capa-rules
git clone --depth 1 https://github.com/MicrosoftDocs/sdk-api.git vendor/sdk-api
git clone --depth 1 https://github.com/MicrosoftDocs/windows-driver-docs-ddi.git \
          vendor/windows-driver-docs-ddi

python etl/build_index.py
```

The build verifies itself and exits non-zero on failure. `--no-sdk-api` builds a
1.5 MB MalAPI-only index in a second, which is enough for most iteration.

The ETL is also usable on its own, without x64dbg:

```bash
python etl/lookup.py kernel32.CreateProcessW
python etl/lookup.py --search "process hollowing"
python etl/capabilities.py --for-api VirtualAllocEx
python etl/capabilities.py --pe C:/Windows/System32/notepad.exe --high-confidence
```

## Layout

```
etl/                    Python, build-time only
  build_index.py        orchestrator -> dist/apisignature.db
  normalize.py          THE name resolver (mirrored by src/normalize.cpp)
  capabilities.py       capa matching; reference impl for src/capa_eval.cpp
  lookup.py             query the index; reference impl for src/index.cpp
  sources/              malapi.py, sdk_api.py, capa.py
src/                    C++ runtime
  plugin.cpp            entry points, selection callback, Qt tab
  index.cpp             SQLite reader
  render.cpp            panel HTML
  normalize.cpp         mirror of etl/normalize.py
build.ps1               builds .dp32 + .dp64 with the right toolset and Qt kit
install.ps1             installs into x64dbg
package.ps1             cuts a release archive
tests/                  C++ tests (no x64dbg or Qt required)
```

## Licence and attribution

Source code is MIT licensed — see [LICENSE](LICENSE).

The prebuilt index redistributes third-party content under its own terms. These
notices also travel inside the index and appear in the plugin's About view.

- Windows API reference documentation © Microsoft Corporation, from
  [sdk-api](https://github.com/MicrosoftDocs/sdk-api) and
  [windows-driver-docs-ddi](https://github.com/MicrosoftDocs/windows-driver-docs-ddi),
  licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Text is
  unmodified apart from rendering to HTML.
- API abuse descriptions and attack categories from
  [malapi.io](https://malapi.io), curated by mr.d0x and contributors. This
  project is not affiliated with or endorsed by malapi.io.
- API combination rules from [capa-rules](https://github.com/mandiant/capa-rules),
  Apache License 2.0.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full notices.
