namespace PcapViewer.Core.Models;

/// <summary>A node in the protocol dissection tree (mirrors Wireshark's detail pane).</summary>
public sealed class PacketDetailNode
{
    public string Label { get; init; } = "";

    /// <summary>Raw field value (hex), when present.</summary>
    public string? Value { get; init; }

    public List<PacketDetailNode> Children { get; init; } = new();
}

/// <summary>Full deep dissection of a single packet.</summary>
public sealed class PacketDetail
{
    public int Number { get; init; }

    /// <summary>Top-level protocol layers (frame, eth, ip, tcp, ...).</summary>
    public List<PacketDetailNode> Protocols { get; init; } = new();

    /// <summary>Classic offset / hex / ASCII dump of the frame bytes.</summary>
    public string HexDump { get; set; } = "";
}
