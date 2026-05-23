namespace PcapViewer.Core.Models;

/// <summary>Traffic between two endpoints, as reported by tshark's conversation statistics.</summary>
public sealed class Conversation
{
    /// <summary>Conversation layer: tcp, udp, ip, ipv6 or eth.</summary>
    public string Protocol { get; init; } = "";

    public string EndpointA { get; init; } = "";
    public string EndpointB { get; init; } = "";

    public long FramesAToB { get; init; }
    public long BytesAToB { get; init; }
    public long FramesBToA { get; init; }
    public long BytesBToA { get; init; }
    public long TotalFrames { get; init; }
    public long TotalBytes { get; init; }

    public double RelativeStartSeconds { get; init; }
    public double DurationSeconds { get; init; }
}
