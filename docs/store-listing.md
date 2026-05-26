# Microsoft Store listing — SimplePCapViewer

Copy each section into the matching Partner Center field. Character limits are
noted; the drafts below are within them.

---

## Display name
SimplePCapViewer

## Short description (≤ 200 characters)
A Wireshark-style pcap and pcapng viewer that exposes captures to AI assistants via an embedded Model Context Protocol (MCP) server, so Claude can search, dissect, and explain network traffic for you.

## Description (≤ 10 000 characters)

SimplePCapViewer is a fast, native Windows viewer for Wireshark-style packet capture files (.pcap, .pcapng, .cap) with a unique twist: it ships an embedded Model Context Protocol (MCP) server, so AI assistants like Claude can search, dissect, and reason about your captures in conversation.

WHAT YOU GET
• Instant packet list backed by a pure-managed pcap/pcapng reader — no Npcap driver required just to open files.
• Full Wireshark display-filter search (http.request, ip.addr == 10.0.0.5, tcp.port == 443, …) via tshark.
• Per-field protocol dissection tree and hex/ASCII view for any packet.
• Right-click copy on packet rows (whole row, source, destination, protocol, info) and on detail-tree nodes (whole subtree, or a single line).
• TLS / HTTPS decryption when you provide a key log file (SSLKEYLOGFILE). Works with Chromium browsers, Firefox, curl, Node, Python — any application that honours the standard variable.
• Event log and ETW trace correlation: attach .evtx and .etl files to the session so you can cross-reference DNS lookups, Schannel TLS errors, Wi-Fi events, firewall verdicts, and per-socket PIDs against the wire.
• Built-in MCP server over streamable HTTP. Toggle it on and connect Claude Code, Claude Desktop, VS Code, or any MCP-compatible client to read whatever capture you currently have open. A one-click dialog gives you copy-paste configuration snippets for each client.

WHY MCP?
The MCP server turns the viewer into a primary source for AI-assisted network analysis. Instead of describing a capture to your assistant, the assistant can directly: list packets, run display filters, dissect a specific frame, get conversation statistics, follow a TCP stream, extract HTTP objects, attach event logs, and correlate events with packets by time. All over a local loopback HTTP endpoint — no cloud, no upload.

LOCAL-ONLY BY DESIGN
Nothing is uploaded. SimplePCapViewer makes no outbound network connections, runs no telemetry, and contains no analytics. The MCP server binds to 127.0.0.1 only — it is not reachable from other machines on your network or from the internet.

ADVANCED FEATURES (REQUIRE WIRESHARK INSTALLED)
Display-filter search, deep dissection, statistics, follow-stream, and object extraction shell out to tshark.exe (the Wireshark CLI). If Wireshark is not installed, the viewer still opens captures and shows the fast packet list and hex bytes; the tshark-dependent features display a clear "install Wireshark" message and degrade gracefully.

WHO IT'S FOR
• Network engineers and security researchers who want AI assistance reasoning about a capture without ever leaving their machine.
• Developers debugging HTTP, TLS, or RPC issues alongside Windows event logs.
• Anyone who finds Wireshark powerful but slow to navigate by hand.

OPEN SOURCE
Source, releases, and issue tracker: https://github.com/guscatalano/SimplePCapViewer

## Product features (≤ 20 items, each ≤ 200 characters)

- Native Windows viewer for .pcap and .pcapng (Wireshark) capture files.
- Embedded Model Context Protocol (MCP) server — let Claude and other AI assistants search and analyse your captures.
- Instant packet list with no Npcap driver dependency to open files.
- Full Wireshark display-filter search via tshark.
- Per-field protocol dissection tree and hex/ASCII view for every packet.
- Decrypt TLS / HTTPS when you supply an SSLKEYLOGFILE key log.
- Attach Windows event logs (.evtx) and ETW traces (.etl) for OS-side correlation.
- Follow TCP / UDP / HTTP / TLS streams and extract HTTP / SMB / TFTP objects.
- Right-click any packet row or dissection node to copy data to the clipboard.
- MCP client setup dialog with copy-paste snippets for Claude Code, Claude Desktop, and VS Code.
- Loopback-only network footprint — no telemetry, no cloud, runs entirely on your machine.

## Search terms (≤ 7 terms, each ≤ 30 characters)

1. pcap viewer
2. pcapng
3. wireshark
4. packet capture
5. mcp server
6. tls decrypt
7. network analysis

## Copyright and trademark info
© 2026 Gus Catalano

## Suggested category
**Developer tools** → *Networking* (or *Utilities & tools*)

## System requirements
- Architecture: x64
- Minimum OS: Windows 10, version 1809 (build 10.0.17763) or later
- Recommended: [Wireshark](https://www.wireshark.org/) installed for display-filter search, deep dissection, and statistics features

## Privacy policy URL
https://github.com/guscatalano/SimplePCapViewer/blob/main/PRIVACY.md

## Support contact
- Email: gus@guscatalano.com
- Issues: https://github.com/guscatalano/SimplePCapViewer/issues

## Release notes — version 1.1.0 ("What's new" field)
Initial Store release. A searchable .pcap / .pcapng viewer with an embedded Model Context Protocol (MCP) server for AI-assisted analysis, TLS / HTTPS decryption from an SSLKEYLOGFILE key log, and Windows event log / ETW trace correlation. No telemetry, no cloud — everything runs locally.
