namespace PcapViewer.Core.Events;

/// <summary>
/// One row of an attached .evtx or .etl file, normalised across both formats.
/// </summary>
public sealed class EventEntry
{
    /// <summary>UTC timestamp of the event.</summary>
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>"evtx" or "etl".</summary>
    public string Source { get; init; } = "";

    /// <summary>The publisher / ETW provider name (e.g. "Microsoft-Windows-DNS-Client", "Schannel").</summary>
    public string Provider { get; init; } = "";

    /// <summary>Event Log channel (.evtx) — e.g. "System", "Microsoft-Windows-DNS-Client/Operational". Empty for .etl.</summary>
    public string Channel { get; init; } = "";

    public int EventId { get; init; }

    /// <summary>"Information", "Warning", "Error", "Critical", "Verbose".</summary>
    public string Level { get; init; } = "";

    public int? ProcessId { get; init; }

    /// <summary>Human-readable rendering of the event.</summary>
    public string Message { get; init; } = "";

    /// <summary>The .evtx or .etl file this came from.</summary>
    public string AttachmentFile { get; init; } = "";

    /// <summary>Whether the publisher/channel is one of the network-related ones (see <see cref="NetworkProviders"/>).</summary>
    public bool IsNetwork { get; init; }
}
