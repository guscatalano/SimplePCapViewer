namespace PcapViewer.Core.Models;

/// <summary>Summary metadata about an opened capture file.</summary>
public sealed class CaptureInfo
{
    public string FilePath { get; init; } = "";
    public string FileName => Path.GetFileName(FilePath);
    public long FileSizeBytes { get; init; }

    /// <summary>"pcap" or "pcapng".</summary>
    public string FileFormat { get; init; } = "";

    /// <summary>Human-readable data link type, e.g. "Ethernet".</summary>
    public string LinkType { get; init; } = "";

    public int PacketCount { get; init; }
    public DateTimeOffset? FirstPacketTime { get; init; }
    public DateTimeOffset? LastPacketTime { get; init; }
    public double DurationSeconds { get; init; }
}
