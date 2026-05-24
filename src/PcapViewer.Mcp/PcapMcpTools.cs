using System.ComponentModel;
using ModelContextProtocol.Server;
using PcapViewer.Core;
using PcapViewer.Core.Events;
using PcapViewer.Core.Models;

namespace PcapViewer.Mcp;

/// <summary>
/// MCP tools that expose the capture currently open in the SimplePCapViewer window.
/// Every tool operates on <see cref="PcapSession.Current"/> and returns a JSON string.
/// </summary>
[McpServerToolType]
public sealed class PcapMcpTools
{
    private PcapMcpTools() { } // tools are static; this type is never instantiated

    [McpServerTool(Name = "get_capture_info")]
    [Description("Get metadata about the capture file currently open in the viewer: file name, " +
                 "size, format (pcap/pcapng), data link type, packet count, capture time span, " +
                 "and whether tshark is available for deep analysis. Call this first to confirm a capture is loaded.")]
    public static string GetCaptureInfo()
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var info = document.Info;
        return McpJson.Serialize(new
        {
            info.FileName,
            info.FilePath,
            info.FileSizeBytes,
            info.FileFormat,
            info.LinkType,
            info.PacketCount,
            firstPacketTime = info.FirstPacketTime,
            lastPacketTime = info.LastPacketTime,
            info.DurationSeconds,
            tsharkAvailable = PcapSession.Current.Tshark.IsAvailable,
            tlsKeyLogFile = PcapSession.Current.TlsKeyLogPath,
        });
    }

    [McpServerTool(Name = "set_tls_keylog")]
    [Description("Enable TLS/HTTPS decryption by pointing the server at a TLS key log file — " +
                 "the file an app writes when the SSLKEYLOGFILE environment variable is set " +
                 "(Chromium browsers, Firefox, curl, Node, Python, etc. all support it). " +
                 "Once set, search_packets, get_packet_detail, follow_stream and extract_objects " +
                 "all decrypt TLS. Pass an empty string to turn decryption back off.")]
    public static string SetTlsKeyLog(
        [Description("Absolute path to the TLS key log file; empty string to disable decryption.")]
        string keyLogPath)
    {
        keyLogPath = keyLogPath?.Trim() ?? "";

        if (keyLogPath.Length == 0)
        {
            PcapSession.Current.TlsKeyLogPath = null;
            return McpJson.Serialize(new
            {
                tlsKeyLogFile = (string?)null,
                message = "TLS decryption disabled.",
            });
        }

        if (!File.Exists(keyLogPath))
            return McpJson.Failure($"TLS key log file not found: {keyLogPath}");

        PcapSession.Current.TlsKeyLogPath = keyLogPath;
        return McpJson.Serialize(new
        {
            tlsKeyLogFile = keyLogPath,
            message = "TLS decryption enabled. Re-run search_packets or get_packet_detail to see decrypted traffic.",
        });
    }

    [McpServerTool(Name = "list_packets")]
    [Description("List packets from the open capture in capture order, with one summary row each " +
                 "(number, time, source, destination, protocol, length, info). Fast — served from " +
                 "the in-memory index. Use 'offset' and 'limit' to page through large captures. " +
                 "To filter, use search_packets instead.")]
    public static string ListPackets(
        [Description("Zero-based index of the first packet to return.")] int offset = 0,
        [Description("Maximum number of packets to return (1-500).")] int limit = 50)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 500);

        var page = document.Packets.Skip(offset).Take(limit).Select(ToDto).ToList();
        return McpJson.Serialize(new
        {
            total = document.Packets.Count,
            offset,
            count = page.Count,
            packets = page,
        });
    }

    [McpServerTool(Name = "search_packets")]
    [Description("Search the open capture using Wireshark display-filter syntax and return matching " +
                 "packet summaries. Examples of filters: 'http.request', 'ip.addr == 10.0.0.5', " +
                 "'tcp.port == 443', 'dns', 'tcp.flags.syn == 1 && tcp.flags.ack == 0', " +
                 "'frame contains \"password\"'. Results are paginated with offset/limit. Requires tshark.")]
    public static async Task<string> SearchPackets(
        [Description("A Wireshark display filter. Leave empty to match every packet.")] string displayFilter,
        [Description("Zero-based index of the first match to return.")] int offset = 0,
        [Description("Maximum number of matches to return (1-500).")] int limit = 50,
        CancellationToken cancellationToken = default)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
            return McpJson.Failure("tshark (Wireshark) is not installed; display-filter search is unavailable.");

        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 500);

        try
        {
            var matches = await tshark.SearchAsync(document.FilePath, displayFilter, cancellationToken);
            var page = matches.Skip(offset).Take(limit).Select(ToDto).ToList();
            return McpJson.Serialize(new
            {
                displayFilter,
                total = matches.Count,
                offset,
                count = page.Count,
                packets = page,
            });
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    [McpServerTool(Name = "get_packet_detail")]
    [Description("Get the full, per-field protocol dissection tree for one packet (the equivalent " +
                 "of Wireshark's detail pane), plus a hex/ASCII dump of the raw bytes. " +
                 "Use the packet number from list_packets or search_packets. Requires tshark.")]
    public static async Task<string> GetPacketDetail(
        [Description("1-based packet number to dissect.")] int frameNumber,
        CancellationToken cancellationToken = default)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
            return McpJson.Failure("tshark (Wireshark) is not installed; deep dissection is unavailable.");

        try
        {
            var detail = await tshark.GetDetailAsync(document.FilePath, frameNumber, cancellationToken);
            detail.HexDump = document.GetHexDump(frameNumber);
            return McpJson.Serialize(detail);
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    [McpServerTool(Name = "get_conversations")]
    [Description("Get conversation (flow) statistics for the open capture: every pair of endpoints " +
                 "that exchanged traffic, with packet and byte counts in each direction, start time " +
                 "and duration. Useful for finding top talkers. Requires tshark.")]
    public static async Task<string> GetConversations(
        [Description("Conversation layer: 'tcp', 'udp', 'ip', 'ipv6' or 'eth'.")] string type = "tcp",
        CancellationToken cancellationToken = default)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
            return McpJson.Failure("tshark (Wireshark) is not installed; statistics are unavailable.");

        try
        {
            var conversations = await tshark.GetConversationsAsync(document.FilePath, type, cancellationToken);
            return McpJson.Serialize(new
            {
                type,
                count = conversations.Count,
                conversations,
            });
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    [McpServerTool(Name = "get_protocol_hierarchy")]
    [Description("Get the protocol hierarchy of the open capture as a tree — every protocol seen, " +
                 "nested by layer, with frame and byte counts. A fast way to understand what kinds " +
                 "of traffic the capture contains. Requires tshark.")]
    public static async Task<string> GetProtocolHierarchy(CancellationToken cancellationToken = default)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
            return McpJson.Failure("tshark (Wireshark) is not installed; statistics are unavailable.");

        try
        {
            var hierarchy = await tshark.GetProtocolHierarchyAsync(document.FilePath, cancellationToken);
            return McpJson.Serialize(new { protocols = hierarchy });
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    [McpServerTool(Name = "follow_stream")]
    [Description("Reassemble and return a single stream as text — the full back-and-forth payload " +
                 "of one conversation. Get the stream index from a packet's detail (e.g. tcp.stream) " +
                 "or from search_packets. Requires tshark.")]
    public static async Task<string> FollowStream(
        [Description("Stream protocol: 'tcp', 'udp', 'http' or 'tls'.")] string protocol,
        [Description("Zero-based stream index to reassemble.")] int streamIndex,
        [Description("Output mode: 'ascii', 'hex' or 'raw'.")] string mode = "ascii",
        CancellationToken cancellationToken = default)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
            return McpJson.Failure("tshark (Wireshark) is not installed; stream reassembly is unavailable.");

        try
        {
            var content = await tshark.FollowStreamAsync(
                document.FilePath, protocol, streamIndex, mode, cancellationToken);
            return McpJson.Serialize(new { protocol, streamIndex, mode, content });
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    [McpServerTool(Name = "extract_objects")]
    [Description("Carve transferred files/objects out of the open capture and save them to a " +
                 "temporary folder. Returns the list of objects (name, size, saved path). " +
                 "Supported protocols include 'http', 'smb', 'tftp', 'ftp-data', 'imf', 'dicom'. Requires tshark.")]
    public static async Task<string> ExtractObjects(
        [Description("Protocol to extract objects from, e.g. 'http'.")] string protocol = "http",
        CancellationToken cancellationToken = default)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
            return McpJson.Failure("tshark (Wireshark) is not installed; object extraction is unavailable.");

        try
        {
            string outputDirectory = Path.Combine(
                Path.GetTempPath(), "SimplePCapViewer", "objects", Guid.NewGuid().ToString("N"));
            var objects = await tshark.ExtractObjectsAsync(
                document.FilePath, protocol, outputDirectory, cancellationToken);
            return McpJson.Serialize(new
            {
                protocol,
                outputDirectory,
                count = objects.Count,
                objects,
            });
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    // ---- attached event sources (.evtx / .etl) --------------------------

    [McpServerTool(Name = "attach_events")]
    [Description("Attach a Windows Event Log (.evtx) or ETW trace (.etl) file to the session so " +
                 "its events can be searched alongside the pcap. The reader is chosen from the " +
                 "extension. Network-related events (TCPIP, Schannel, DNS-Client, DHCP, WLAN, " +
                 "SMB, WFP, Winsock-AFD, etc.) are tagged automatically.")]
    public static async Task<string> AttachEvents(
        [Description("Absolute path to an .evtx or .etl file.")] string path,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var attachment = await PcapSession.Current.AttachAsync(path, cancellationToken);
            int network = attachment.Events.Count(e => e.IsNetwork);
            return McpJson.Serialize(new
            {
                file = attachment.FileName,
                path = attachment.FilePath,
                kind = attachment.Kind,
                eventCount = attachment.Events.Count,
                networkEventCount = network,
            });
        }
        catch (Exception ex)
        {
            return McpJson.Failure(ex.Message);
        }
    }

    [McpServerTool(Name = "list_attachments")]
    [Description("List the .evtx / .etl files attached to the session, with the number of events " +
                 "each contributed (total and network-relevant).")]
    public static string ListAttachments()
    {
        var attachments = PcapSession.Current.Attachments;
        return McpJson.Serialize(new
        {
            count = attachments.Count,
            totalEvents = PcapSession.Current.EventIndex.Count,
            attachments = attachments.Select(a => new
            {
                a.FileName,
                a.FilePath,
                a.Kind,
                eventCount = a.Events.Count,
                networkEventCount = a.Events.Count(e => e.IsNetwork),
            }),
        });
    }

    [McpServerTool(Name = "detach_events")]
    [Description("Remove a previously-attached .evtx / .etl file from the session.")]
    public static string DetachEvents(
        [Description("The attachment's full path, as reported by list_attachments.")] string path)
        => McpJson.Serialize(new { removed = PcapSession.Current.Detach(path), path });

    [McpServerTool(Name = "search_events")]
    [Description("Search events from every attached .evtx / .etl file. Defaults to network-related " +
                 "events only (TCP/IP, Schannel, DNS, DHCP, WLAN, SMB, WFP, …). Set networkOnly=false " +
                 "to include everything in the attached files.")]
    public static string SearchEvents(
        [Description("Free-text query matched against the event message, provider, channel, and event ID. Optional.")]
        string? query = null,
        [Description("Restrict to events whose provider or channel name contains this string. Optional.")]
        string? providerOrChannel = null,
        [Description("Restrict to a level: Critical / Error / Warning / Information / Verbose. Optional.")]
        string? level = null,
        [Description("If true (default), only return events from known network-related providers/channels.")]
        bool networkOnly = true,
        [Description("Zero-based offset into the result list.")] int offset = 0,
        [Description("Maximum number of events to return (1-500).")] int limit = 50)
    {
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 500);

        var matches = PcapSession.Current.EventIndex
            .Search(query, providerOrChannel, level, from: null, to: null, networkOnly)
            .ToList();

        var page = matches.Skip(offset).Take(limit).Select(ToDto).ToList();
        return McpJson.Serialize(new
        {
            total = matches.Count,
            offset,
            count = page.Count,
            networkOnly,
            events = page,
        });
    }

    [McpServerTool(Name = "events_near_packet")]
    [Description("Return events whose timestamps fall within a window around a packet's capture time. " +
                 "Use this to correlate packet-level activity with Schannel TLS failures, DNS lookups, " +
                 "WLAN events, etc.")]
    public static string EventsNearPacket(
        [Description("1-based packet number from the open capture.")] int frameNumber,
        [Description("Seconds before the packet to include.")] double secondsBefore = 2,
        [Description("Seconds after the packet to include.")] double secondsAfter = 2,
        [Description("If true (default), only network-related events.")] bool networkOnly = true,
        [Description("Maximum number of events to return (1-500).")] int limit = 100)
    {
        var document = PcapSession.Current.Document;
        if (document is null)
            return McpJson.NoCapture();
        var frame = document.GetFrame(frameNumber);
        if (frame is null)
            return McpJson.Failure($"No such frame: {frameNumber}");

        limit = Math.Clamp(limit, 1, 500);
        var window = PcapSession.Current.EventIndex
            .InWindow(frame.Timestamp.ToUniversalTime(),
                      TimeSpan.FromSeconds(Math.Max(0, secondsBefore)),
                      TimeSpan.FromSeconds(Math.Max(0, secondsAfter)),
                      networkOnly)
            .Take(limit)
            .Select(ToDto)
            .ToList();

        return McpJson.Serialize(new
        {
            frameNumber,
            frameTime = frame.Timestamp,
            secondsBefore,
            secondsAfter,
            networkOnly,
            count = window.Count,
            events = window,
        });
    }

    private static object ToDto(PacketSummary p) => new
    {
        p.Number,
        time = p.Timestamp,
        p.TimeOffsetSeconds,
        p.Source,
        p.Destination,
        p.Protocol,
        p.Length,
        p.Info,
    };

    private static object ToDto(EventEntry e) => new
    {
        e.Timestamp,
        e.Source,
        e.Provider,
        e.Channel,
        e.EventId,
        e.Level,
        e.ProcessId,
        e.Message,
        file = Path.GetFileName(e.AttachmentFile),
        e.IsNetwork,
    };
}
