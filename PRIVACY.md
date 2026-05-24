# Privacy Policy for SimplePCapViewer

**Effective date:** 23 May 2026

## Summary

SimplePCapViewer is a local utility for viewing Wireshark-style packet captures
(`.pcap` / `.pcapng`) and optionally correlating them with Windows event logs
(`.evtx`) and ETW traces (`.etl`). **The application does not collect, transmit, or
share any of your data.** Everything stays on your computer.

## Information the application does not collect

We do not:

- collect, store, or transmit any personal information,
- send any analytics or telemetry to the developer or any third party,
- contact any service controlled by the developer,
- check for updates over the network,
- create user accounts, log-ins, or profiles of any kind.

The application makes **no outbound network connections on its own.**

## Information the application accesses locally

When you use specific features, SimplePCapViewer reads files **you explicitly
select** from your computer:

- **Capture files** (`.pcap`, `.pcapng`, `.cap`) you open — read-only.
- **Event log / ETW trace files** (`.evtx`, `.etl`) you attach for correlation —
  read-only.
- **TLS key log files** (an `SSLKEYLOGFILE` you point the application at) —
  read-only, used to decrypt TLS in the capture you have open.

The application reads these files locally on demand. **Nothing is uploaded.**

## Local process execution

SimplePCapViewer invokes Wireshark's `tshark.exe` as a local subprocess when you
use display-filter search, deep packet dissection, conversation/protocol
statistics, stream reassembly, or object extraction. `tshark.exe` runs entirely
on your computer with the same access as SimplePCapViewer itself.
SimplePCapViewer does not bundle, redistribute, or modify Wireshark.

## Local MCP server (loopback only)

When you enable the **MCP server** toggle, SimplePCapViewer starts an HTTP
server bound to the loopback address `127.0.0.1`. This is a localhost-only port
— it is **not** reachable from other computers on your network or from the
internet.

While the server is running, any process on your computer that connects to
`http://127.0.0.1:<port>` can call the application's MCP tools to read the
contents of the capture you currently have open and the events you have
attached. Turn the toggle off, or close the application, to stop the server.

## Children's privacy

This application is not directed at children and does not collect any
information from anyone, including children.

## Third-party services

The application does not use third-party analytics, advertising networks, or
cloud services. It bundles open-source libraries that run locally:

- [PacketDotNet](https://github.com/dotpcap/packetdotnet) — packet parsing
- [Microsoft.Diagnostics.Tracing.TraceEvent](https://github.com/microsoft/perfview/tree/main/src/TraceEvent) — ETW trace reading
- [ModelContextProtocol .NET SDK](https://github.com/modelcontextprotocol/csharp-sdk) — MCP server
- [CommunityToolkit.Mvvm](https://learn.microsoft.com/dotnet/communitytoolkit/mvvm/) — view-model helpers
- [Windows App SDK](https://learn.microsoft.com/windows/apps/windows-app-sdk/) — application framework

None of these libraries transmit your data.

## Changes to this policy

If a future version of the application changes how it accesses or handles data,
this policy will be updated and the effective date at the top revised. Material
changes will also be noted in the application's release notes.

## Contact

For questions about this privacy policy or the application:

**Gus Catalano** — gus@guscatalano.com
Issues and source: <https://github.com/guscatalano/SimplePCapViewer>
