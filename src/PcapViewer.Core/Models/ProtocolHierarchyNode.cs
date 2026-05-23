namespace PcapViewer.Core.Models;

/// <summary>One protocol in the capture's protocol hierarchy tree (tshark -z io,phs).</summary>
public sealed class ProtocolHierarchyNode
{
    public string Protocol { get; init; } = "";
    public long Frames { get; init; }
    public long Bytes { get; init; }

    /// <summary>Nesting depth (0 = top level).</summary>
    public int Depth { get; init; }

    public List<ProtocolHierarchyNode> Children { get; init; } = new();
}
