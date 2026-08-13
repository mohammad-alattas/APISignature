# APISignature

An x64dbg/x32dbg plugin for malware analysts and reverse engineers. It brings a
reference covering **44,000+ Windows API functions** directly into the debugger:
Microsoft's official documentation alongside [malapi.io](https://malapi.io)'s
description of how each function gets abused.

Select a call in the disassembly and a docked panel fills in — Microsoft's
documentation, malapi.io's malicious-use description, and its attack categories.

Everything is offline. One DLL and one index file — no network, no Python, no
second process.

## How it helps

**Stop leaving the debugger.** The documentation for the call under your cursor
appears in a docked tab: description, parameters, return values, header.

**See why malware calls it.** For the most used 369 APIs malapi.io catalogues, the panel
leads with the malicious use and tags the attack category — Injection, Evasion,
Spying, Ransomware, Anti-Debugging, Enumeration, Internet, Helper. When an API
*isn't* in that catalogue the panel says so explicitly, so absence is an answer
rather than a blank.

**Works in an isolated VM.** Analysis machines usually have no internet on
purpose. The whole reference is a local SQLite file.

**Finds the API you actually selected.** Real disassembly shows `CreateProcessW`,
`ZwOpenProcess`, `KERNELBASE.`-forwarded calls and `__imp_` thunks. Lookups fold
A/W spellings, Nt/Zw pairs, forwarders and decoration automatically. When the
entry shown was written against a different spelling, the panel says so rather
than quietly attributing one spelling's write-up to another.

**Search the whole corpus.** `Ctrl+Shift+A` runs a full-text search across every
API description, not just names.

## Requirements

- Windows
- **x64dbg 2025-06-30 or newer.** That release moved x64dbg to Visual
  Studio 2022 and Qt 5.12, which is what makes a docked panel from a plugin
  possible at all. Older snapshots will not load it.
- ~50 MB of disk per architecture — the index is copied beside each plugin

Nothing else. No Python, no runtime, no configuration.

## Installation

1. **Download** the latest `APISignature-*-win.zip` from the
   [releases page](../../releases).
2. **Close x64dbg**, extract the archive, then run:

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

| Copy these | Into |
|---|---|
| `APISignature.dp64` + `apisignature.db` | `<x64dbg>\release\x64\plugins\` |
| `APISignature.dp32` + `apisignature.db` | `<x64dbg>\release\x32\plugins\` |

`apisignature.db` must sit **beside** the plugin — that is where the plugin looks
for it. Installing the DLL alone gives you a plugin that loads and then reports
"No index loaded".

</details>

## Using it

The panel follows your selection in the disassembly automatically.

| | |
|---|---|
| **Pin** | Stops the panel following the selection, so you can read while you scroll |
| **Search** | `Ctrl+Shift+A` — full-text search across the documentation |
| **About** | Index location and attribution for the bundled data |

## Building from source

Only needed if you want to change the plugin.

```powershell
.\build.ps1 -X64dbgRoot "C:\path\to\x64dbg"
```

The toolchain has two sharp edges — Qt must match x64dbg's build exactly, and the
newest MSVC cannot compile Qt 5.12 — both of which `build.ps1` handles. See
[docs/BUILDING.md](docs/BUILDING.md).

## Reference

| Source | What it provides |
|---|---|
| [MicrosoftDocs/sdk-api](https://github.com/MicrosoftDocs/sdk-api) + [windows-driver-docs-ddi](https://github.com/MicrosoftDocs/windows-driver-docs-ddi) | Windows API reference documentation |
| [malapi.io](https://malapi.io) | Malicious-use descriptions and attack categories |

## Licence

Source code is MIT licensed — see [LICENSE](LICENSE).

The prebuilt index redistributes third-party content under its own terms. These
notices also travel inside the index and appear in the plugin's About view.

- Windows API reference documentation © Microsoft Corporation, licensed
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Text is unmodified
  apart from rendering to HTML.
- API abuse descriptions and attack categories from
  [malapi.io](https://malapi.io), curated by mr.d0x and contributors. This
  project is not affiliated with or endorsed by malapi.io.
- API combination rules from [capa-rules](https://github.com/mandiant/capa-rules),
  Apache License 2.0.

Full notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
