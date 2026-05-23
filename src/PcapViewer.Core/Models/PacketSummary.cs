using System.Globalization;

namespace PcapViewer.Core.Models;

/// <summary>One row of the packet list — the same columns Wireshark shows by default.</summary>
public sealed class PacketSummary
{
    public int Number { get; init; }
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Seconds elapsed since the first packet in the capture.</summary>
    public double TimeOffsetSeconds { get; init; }

    /// <summary>Relative capture time formatted for display, like Wireshark's Time column.</summary>
    public string TimeDisplay => TimeOffsetSeconds.ToString("0.000000", CultureInfo.InvariantCulture);

    public string Source { get; init; } = "";
    public string Destination { get; init; } = "";
    public string Protocol { get; init; } = "";

    /// <summary>Frame length on the wire, in bytes.</summary>
    public int Length { get; init; }

    public string Info { get; init; } = "";
}
