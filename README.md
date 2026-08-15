# APISignature

https://github.com/user-attachments/assets/e98aeee5-623d-4c4e-bf29-0e13a5357572


An x64dbg/x32dbg plugin for malware analysts and reverse engineers. It brings a
reference covering **44,000+ Windows API functions** directly into the debugger:
Microsoft's official documentation alongside [malapi.io](https://malapi.io)'s 
& Capa rules to understand the API, abuse methods, and detect patterns. 

Select a call in the debugger and a docked panel fills in

1. Microsoft's official documentation.
2. Malapi.io's malicious-use description, and its attack categories.
3. capa rule pattern detection the known malicious API combinations that call
   belongs to, and which parts are already present in the target.

The plugin is entirely offline. One DLL and one index file — no network, no
Python, no second process. An **optional** MCP server ships alongside it for anyone
who wants an AI assistant to query the same index.

# How it helps

**1. Stop leaving the debugger:** The documentation for the call under your cursor
appears in a docked tab: description, parameters, return values, header.

**2. See why malware calls it:** For the most used 369 APIs malapi.io catalogues, the panel
leads with the malicious use and tags the attack category — Injection, Evasion,
Spying, Ransomware, Anti-Debugging, Enumeration, Internet, Helper. When an API
*isn't* in that catalogue the panel says so explicitly, so absence is an answer
rather than a blank.

**3. See the patterns, not just the call:** Each API shows the capa rules it
takes part in, with the members you already have highlighted against the ones you
don't. The **Capabilities** button answers the same question for the whole
target: press it, and the imports of every loaded module are matched against
capa's rules. Press it again after a sample unpacks and anything new is marked.

**4. Works in an isolated VM:** Analysis machines usually have no internet on
purpose. The whole reference is a local SQLite file.

**5. Search the whole corpus:** `Ctrl+Shift+A` or the Search bar runs a full-text
search across every API description, not just names.

## Quick Start

1. **Download** the latest `APISignature-*-win.zip` from the
   [releases page](../../releases).
2. **Close x64dbg in case it's open**, extract the archive, then copy:

| Copy these | Into |
|---|---|
| `APISignature.dp64` + `apisignature.db` | `<x64dbg>\release\x64\plugins\` |
| `APISignature.dp32` + `apisignature.db` | `<x32dbg>\release\x32\plugins\` |

`apisignature.db` must sit **beside** the plugin, that's where the plugin looks
for it. Installing the DLL alone gives you a plugin that loads and then reports
"No index loaded".

3. **Start x64dbg.** An `APISignature` tab appears in the main tab bar.

## Using it

The panel follows your selection in the debugger automatically.

| Action | How |
|---|---|
| **Search** | `Ctrl+Shift+A` or the Search bar; full-text search across the documentation |
| **Capabilities** | The Capabilities button; what the loaded modules' imports say the target can do |
| **About** | Index location and attribution for the bundled data |

## Using it with an AI assistant (MCP) (OPTIONAL)

`mcp_server/` is an optional [MCP](https://modelcontextprotocol.io) server that
gives an AI assistant the same index, so it looks Windows APIs up instead of
recalling them. A model has read plenty of Microsoft documentation, but it has
not reliably memorised malapi.io's abuse notes or capa's combinations — and when
it hasn't, it produces something plausible rather than saying it doesn't know.

There is no AI code in the server and no network access: it reads the local
SQLite file and returns text.

```bash
pip install -r mcp_server/requirements.txt
```

For Claude Code:

```bash
claude mcp add apisignature -- python "D:/path/to/APISignature/mcp_server/server.py"
```

For Claude Desktop, add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "apisignature": {
      "command": "python",
      "args": ["D:\\path\\to\\APISignature\\mcp_server\\server.py"],
      "env": { "APISIGNATURE_DB": "D:\\path\\to\\apisignature.db" }
    }
  }
}
```

It speaks standard MCP over stdio, so Cursor, Continue or your own agent work
too. The tools:

| Tool | What it answers |
|---|---|
| `lookup_api` | What does this API do, and how does malware abuse it? |
| `search_apis` | Which APIs relate to "process hollowing"? |
| `capa_rules_for_api` | Which malicious combinations does this API take part in? |
| `analyze_api_set` | Given these imports, what is the sample capable of? |
| `list_attack_categories` | The eight malapi.io categories and their sizes |
| `apis_by_attack` | Which APIs are in the Injection category? |
| `index_info` | Coverage, build date, attribution |

See [mcp_server/README.md](mcp_server/README.md) for details.

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
| [mandiant/capa-rules](https://github.com/mandiant/capa-rules) | The malicious API combinations behind the capa sections |

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
- API combination rules from [mandiant/capa-rules](https://github.com/mandiant/capa-rules),
  Apache License 2.0.

Full notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
