namespace PcapViewer.Core.Models;

/// <summary>A single captured frame with its raw bytes, as read from the capture file.</summary>
public sealed class RawFrame
{
    /// <summary>1-based packet number, matching Wireshark's "No." column.</summary>
    public int Number { get; init; }

    /// <summary>Absolute capture timestamp.</summary>
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Number of bytes actually stored in the file for this frame.</summary>
    public int CapturedLength { get; init; }

    /// <summary>Length of the frame on the wire (may exceed <see cref="CapturedLength"/> if truncated).</summary>
    public int OriginalLength { get; init; }

    /// <summary>Captured frame bytes.</summary>
    public byte[] Data { get; init; } = Array.Empty<byte>();

    /// <summary>pcap data link type (DLT) for this frame, e.g. 1 = Ethernet.</summary>
    public int LinkType { get; init; }
}
