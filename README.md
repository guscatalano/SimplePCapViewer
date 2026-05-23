# <img src="src/PcapViewer.App/Assets/AppIcon.png" width="30" align="top" alt=""> SimplePCapViewer

A WinUI 3 viewer for **pcap / pcapng** (Wireshark) capture files that is easy to
search — and, primarily, **exposes packet captures to an MCP server** so an AI
assistant (Claude, etc.) can search and analyze network traffic for you.

## How it works

Capture files are handled in two complementary ways (a hybrid approach):

- **Pure-managed reader** — `pcap` and `pcapng` files are parsed in-process with no
  native dependency (no Npcap needed). This gives an instant packet list and the raw
  bytes for hex display.
- **tshark** — the Wireshark CLI is used on demand for everything that needs full
  Wireshark intelligence: display-filter search, per-field dissection, conversation
  and protocol statistics, stream reassembly and object extraction.

## Projects

| Project | Output | Role |
|---|---|---|
| `src/PcapViewer.Core` | net10.0 library | pcap/pcapng reader, PacketDotNet dissection, tshark wrapper, shared `PcapSession` |
| `src/PcapViewer.Mcp`  | net10.0 exe / library | MCP server (`McpHost` + tools). Runs standalone **and** is hosted in-process by the viewer |
| `src/PcapViewer.App`  | net10.0 WinUI 3 app | The desktop viewer; hosts the embedded MCP server |
| `tests/PcapViewer.Core.Tests` | xUnit | Reader / dissection tests |

## Prerequisites

- Windows 10 (1809+) or Windows 11
- **.NET 10 SDK**
- **Wireshark** — provides `tshark`. Auto-detected on `PATH` and in
  `C:\Program Files\Wireshark`. Required for search, dissection and statistics.
- Visual Studio 2022 is optional — the whole solution builds from the command line.

## Build & test

```sh
dotnet build SimplePCapViewer.slnx                                   # all four projects
dotnet test  tests/PcapViewer.Core.Tests/PcapViewer.Core.Tests.csproj
```

## Installers & CI

`.github/workflows/build.yml` (GitHub Actions) runs on every push/PR: it runs the
tests and builds two installers, uploaded as artifacts. Pushing a `v*` tag also
publishes them to a GitHub Release (the version comes from the tag).

| Installer | Built by | Notes |
|---|---|---|
| **MSIX** (`.msix`) | `dotnet build -p:GenerateAppxPackageOnBuild=true` | Modern packaged install. Built unsigned — sideload requires trusting it. |
| **MSI** (`.msi`) | `dotnet publish` (self-contained) wrapped by WiX 5 | Classic per-machine install to Program Files + Start-menu shortcut. |

To build them locally (run `generate-assets.ps1` first so the icons/tiles exist):

```sh
# MSIX  ->  src/PcapViewer.App/AppPackages/**/*.msix
dotnet build src/PcapViewer.App/PcapViewer.App.csproj -c Release -p:Platform=x64 ^
  -p:GenerateAppxPackageOnBuild=true -p:AppxPackageSigningEnabled=false ^
  -p:UapAppxPackageBuildMode=SideloadOnly -p:AppxBundle=Never

# MSI  ->  SimplePCapViewer.msi
dotnet publish src/PcapViewer.App/PcapViewer.App.csproj -c Release -p:Platform=x64 ^
  -r win-x64 --self-contained true -p:WindowsPackageType=None -o publish
dotnet tool install --global wix --version 5.0.2
wix build installer.wxs -arch x64 -d AppVersion=1.0.0 -out SimplePCapViewer.msi
```

## The MCP server (primary use case)

The MCP server exposes the **currently loaded capture**. Run it either way:

### Standalone

```sh
dotnet run --project src/PcapViewer.Mcp -- sample.pcap --port 7777 [--tls-keylog <file>]
```

A tiny `sample.pcap` is included so you can try it immediately.

### Embedded in the viewer

Launch the WinUI app, open a capture, then flip the **MCP server** switch in the
toolbar. The server then exposes whatever capture is open in the window — switch
files in the viewer and the MCP server follows.

### Connect an MCP client

The server speaks MCP over streamable HTTP. For Claude Code:

```sh
claude mcp add --transport http pcap http://127.0.0.1:7777
```

To make setup easy, the running server **exposes ready-to-paste configuration**
(Claude Code command, Claude Desktop and VS Code JSON blocks):

- printed to the console when the standalone server starts, and
- served as a page at **`http://127.0.0.1:7777/config`** — open it in a browser.

### Tools

| Tool | Purpose |
|---|---|
| `get_capture_info` | File metadata: format, link type, packet count, time span |
| `list_packets` | Paginated packet list (fast, from the in-memory index) |
| `search_packets` | Wireshark display-filter search, e.g. `http.request`, `ip.addr==10.0.0.5` |
| `get_packet_detail` | Full per-field dissection tree + hex dump for one packet |
| `get_conversations` | Conversation/flow statistics (tcp/udp/ip/ipv6/eth) |
| `get_protocol_hierarchy` | Protocol breakdown of the whole capture |
| `follow_stream` | Reassemble a tcp/udp/http/tls stream as text |
| `extract_objects` | Carve transferred files (HTTP, SMB, …) out of the capture |
| `set_tls_keylog` | Point the server at a TLS key log file to decrypt HTTPS everywhere |

## The viewer

- Open `.pcap` / `.pcapng` / `.cap` files.
- **Quick find** — instant case-insensitive filter over the packet list.
- **Display filter** — full Wireshark display-filter syntax (via tshark).
- Select a packet to see its dissection tree and a hex/ASCII dump.
- Toggle the embedded MCP server on/off and set its port.

## Decrypting HTTPS

The viewer and the MCP server can decrypt TLS when given a **key log file** — the file
an app writes when the `SSLKEYLOGFILE` environment variable is set:

```powershell
$env:SSLKEYLOGFILE = "$env:USERPROFILE\Desktop\tls_keys.log"
# then launch the app from that same shell, reproduce the flow, and capture in Wireshark
```

- **Viewer:** click **TLS keys** in the toolbar and pick the key log file.
- **MCP:** call the `set_tls_keylog` tool, or start the standalone server with
  `--tls-keylog <file>`.

Once set, search, dissection, follow-stream and object extraction all show decrypted
traffic. `SSLKEYLOGFILE` is honored by Chromium browsers, Firefox, curl, Node.js and
Python — but **not** by apps that use Windows SChannel (most native Win32 / .NET apps),
which never emit key-log entries.

## Known limitations

- The pure-managed reader loads the whole capture into memory; very large captures
  (multi-GB) are not yet streamed.
