using PcapViewer.Core.Dissection;
using PcapViewer.Core.Models;
using PcapViewer.Core.Pcap;

namespace PcapViewer.Core;

/// <summary>
/// An opened capture file: raw frames plus the fast in-process packet summaries.
/// Deep dissection, display-filter search and statistics go through <see cref="Tshark.TsharkService"/>.
/// </summary>
public sealed class PcapDocument
{
    private readonly IReadOnlyList<RawFrame> _frames;

    private PcapDocument(string path, PcapCapture capture)
    {
        FilePath = path;
        _frames = capture.Frames;

        var start = _frames.Count > 0 ? _frames[0].Timestamp : DateTimeOffset.UnixEpoch;
        var summaries = new List<PacketSummary>(_frames.Count);
        foreach (var frame in _frames)
            summaries.Add(PacketSummaryBuilder.Build(frame, start));
        Packets = summaries;

        Info = new CaptureInfo
        {
            FilePath = path,
            FileSizeBytes = new FileInfo(path).Length,
            FileFormat = capture.Format,
            LinkType = LinkTypeName(capture.PrimaryLinkType),
            PacketCount = _frames.Count,
            FirstPacketTime = _frames.Count > 0 ? _frames[0].Timestamp : null,
            LastPacketTime = _frames.Count > 0 ? _frames[^1].Timestamp : null,
            DurationSeconds = _frames.Count > 0
                ? (_frames[^1].Timestamp - _frames[0].Timestamp).TotalSeconds
                : 0,
        };
    }

    public string FilePath { get; }
    public CaptureInfo Info { get; }

    /// <summary>One summary per packet, in capture order. Index 0 is packet number 1.</summary>
    public IReadOnlyList<PacketSummary> Packets { get; }

    /// <summary>Reads and dissects a capture file. CPU-bound — call from a background thread.</summary>
    public static PcapDocument Load(string path)
        => new(path, PcapFileReader.Read(path));

    /// <summary>Returns the raw frame for a 1-based packet number, or null if out of range.</summary>
    public RawFrame? GetFrame(int number)
        => number >= 1 && number <= _frames.Count ? _frames[number - 1] : null;

    /// <summary>Builds the hex/ASCII dump for a 1-based packet number.</summary>
    public string GetHexDump(int number)
        => GetFrame(number) is { } frame ? HexDump.Format(frame.Data) : "";

    /// <summary>
    /// Instant, case-insensitive substring search across the summary columns.
    /// For Wireshark display-filter syntax use <see cref="Tshark.TsharkService"/> instead.
    /// </summary>
    public IEnumerable<PacketSummary> QuickSearch(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Packets;

        return Packets.Where(p =>
            p.Source.Contains(text, StringComparison.OrdinalIgnoreCase) ||
            p.Destination.Contains(text, StringComparison.OrdinalIgnoreCase) ||
            p.Protocol.Contains(text, StringComparison.OrdinalIgnoreCase) ||
            p.Info.Contains(text, StringComparison.OrdinalIgnoreCase) ||
            p.Number.ToString().Contains(text, StringComparison.OrdinalIgnoreCase));
    }

    private static string LinkTypeName(int linkType) => linkType switch
    {
        0 => "NULL / Loopback",
        1 => "Ethernet",
        9 => "PPP",
        101 => "Raw IP",
        105 => "IEEE 802.11",
        113 => "Linux cooked v1",
        127 => "IEEE 802.11 radiotap",
        147 => "USER0",
        239 => "Wireshark Upper PDU",
        276 => "Linux cooked v2",
        _ => $"Link type {linkType}",
    };
}
