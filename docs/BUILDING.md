# Building

You only need this if you want to change the plugin. Users should install from a
release.

```powershell
.\build.ps1 -X64dbgRoot "C:\path\to\x64dbg"     # both architectures
.\build.ps1 -Arch x64 -Install                   # and copy into x64dbg\plugins
```

Produces `build64\src\APISignature.dp64` and `build32\src\APISignature.dp32`, and
runs the tests.

Use the script rather than calling CMake directly — two things about this
toolchain are non-obvious enough to be worth automating.

## Qt must be the exact version x64dbg ships

`GuiAddQWidgetTab` hands a widget across the DLL boundary into x64dbg's own Qt,
which then calls virtual functions on it. There is no version negotiation and no
error path — a mismatch corrupts memory rather than failing to link.

Verified 5.12.12; confirm yours with
`(Get-Item release\x64\Qt5Core.dll).VersionInfo`. CMake fails the configure step
on a mismatch rather than letting you find out at runtime.

## The newest MSVC cannot compile Qt 5.12

Toolset 14.51, which VS 2026 installs by default, removed
`stdext::checked_array_iterator`. Qt 5.12 still uses it, and the failure is pages
of template errors from inside `qlist.h` that never name the cause.

Build with **MSVC 14.44 (the v143 toolset)**. Selecting it has a wrinkle: CMake's
VS 2026 generator rejects `-T version=14.44...` under the v145 toolset, so the
tools version has to come from `vcvarsall.bat -vcvars_ver=14.44` and the
generator has to be Ninja. That is all `build.ps1` does.

CMake probes for the extension directly and fails with these instructions rather
than letting the template errors through.

## Host-side tests

These need neither x64dbg nor Qt, so they build with any compiler:

```powershell
cmake -B buildtest -DMALAPI_BUILD_PLUGIN=OFF
cmake --build buildtest
ctest --test-dir buildtest
```

`test_index` runs against `dist\apisignature.db` and skips itself if the index is
not there.

## Cutting a release

```powershell
.\package.ps1 -X64dbgRoot "C:\path\to\x64dbg"
```

Emits `dist\release\APISignature-<version>-win.zip` containing both plugins, the
index, `install.ps1` and the licence notices. Upload that to a GitHub release.

Pass `-NoIndex` for a ~2 MB plugin-only archive, or `-SkipBuild` to package what
is already built.

## Rebuilding the index

The released `apisignature.db` is prebuilt, so this is only for changing what
goes into it. The shallow checkouts come to about 650 MB and the build takes
roughly six minutes.

```bash
git clone --depth 1 https://github.com/MicrosoftDocs/sdk-api.git vendor/sdk-api
git clone --depth 1 https://github.com/MicrosoftDocs/windows-driver-docs-ddi.git \
          vendor/windows-driver-docs-ddi

python etl/build_index.py
```

The build verifies itself and exits non-zero on failure. `--no-sdk-api` builds a
1.5 MB malapi.io-only index in a second, which is enough for most iteration.

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
