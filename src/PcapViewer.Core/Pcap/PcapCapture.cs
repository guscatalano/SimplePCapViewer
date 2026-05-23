using PcapViewer.Core.Models;

namespace PcapViewer.Core.Pcap;

/// <summary>The raw result of reading a capture file: every frame plus file-level metadata.</summary>
public sealed class PcapCapture
{
    public required IReadOnlyList<RawFrame> Frames { get; init; }

    /// <summary>"pcap" or "pcapng".</summary>
    public required string Format { get; init; }

    /// <summary>Data link type of the first interface, used when the capture has a single interface.</summary>
    public int PrimaryLinkType { get; init; }
}
