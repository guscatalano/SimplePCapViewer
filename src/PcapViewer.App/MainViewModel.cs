using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcapViewer.Core;
using PcapViewer.Core.Events;
using PcapViewer.Core.Models;
using PcapViewer.Mcp;

namespace PcapViewer.App;

/// <summary>
/// State and behaviour behind the main window.
/// Uses partial-property [ObservableProperty], the pattern recommended for WinUI 3
/// (the generated properties are visible to the XAML compiler and CsWinRT).
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private const StringComparison Ci = StringComparison.OrdinalIgnoreCase;

    /// <summary>
    /// The "base" packet set the quick-search box filters over: either the full native
    /// packet list, or the result of the last applied display filter.
    /// </summary>
    private IReadOnlyList<PacketSummary> _basePackets = Array.Empty<PacketSummary>();

    public MainViewModel()
    {
        FileName = "No capture open";
        StatusText = "Open a .pcap or .pcapng file to begin.";
        QuickSearch = "";
        DisplayFilter = "";
        ResultInfo = "";
        Timeline = Array.Empty<TimelineRow>();
        HexDump = "";
        DetailStatus = "Select a packet to see its dissection.";
        McpStatus = "MCP server: stopped";
        PortText = McpHost.DefaultPort.ToString();

        PcapSession.Current.AttachmentsChanged += (_, _) => RebuildTimeline();
    }

    [ObservableProperty] public partial string FileName { get; set; }
    [ObservableProperty] public partial string StatusText { get; set; }
    [ObservableProperty] public partial string QuickSearch { get; set; }
    [ObservableProperty] public partial string DisplayFilter { get; set; }
    [ObservableProperty] public partial string ResultInfo { get; set; }
    [ObservableProperty] public partial IReadOnlyList<TimelineRow> Timeline { get; set; }
    [ObservableProperty] public partial TimelineRow? SelectedRow { get; set; }
    [ObservableProperty] public partial string HexDump { get; set; }
    [ObservableProperty] public partial string DetailStatus { get; set; }
    [ObservableProperty] public partial string McpStatus { get; set; }
    [ObservableProperty] public partial string PortText { get; set; }
    [ObservableProperty] public partial bool IsBusy { get; set; }

    /// <summary>Loads a capture file and refreshes the timeline.</summary>
    public async Task OpenAsync(string path)
    {
        IsBusy = true;
        StatusText = $"Loading {Path.GetFileName(path)}…";
        try
        {
            var document = await PcapSession.Current.OpenAsync(path);
            _basePackets = document.Packets;
            QuickSearch = "";
            DisplayFilter = "";
            RebuildTimeline();

            var info = document.Info;
            FileName = $"{info.FileName}   ·   {info.PacketCount:N0} packets   ·   " +
                       $"{info.FileFormat}   ·   {info.LinkType}";
            StatusText = $"Loaded {info.PacketCount:N0} packets " +
                         $"({info.FileSizeBytes / 1024.0:N0} KB, {info.DurationSeconds:N3}s span).";
        }
        catch (Exception ex)
        {
            FileName = "No capture open";
            _basePackets = Array.Empty<PacketSummary>();
            RebuildTimeline();
            StatusText = $"Failed to open file: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    partial void OnQuickSearchChanged(string value) => RebuildTimeline();

    /// <summary>
    /// Re-merges the current packet set with attached events, sorts by timestamp,
    /// and applies the quick-search filter. Cheap; the inputs are already in memory.
    /// </summary>
    private void RebuildTimeline()
    {
        var packetRows = _basePackets.Select(TimelineRow.ForPacket);

        // Anchor event times to the same epoch as packets so the Time column lines up.
        var allEvents = PcapSession.Current.EventIndex.All;
        DateTimeOffset baseTs = _basePackets.Count > 0
            ? _basePackets[0].Timestamp
            : (allEvents.Count > 0 ? allEvents[0].Timestamp : DateTimeOffset.UtcNow);

        // Show every attached event in the timeline. The IsNetwork flag is only used
        // by MCP tools to narrow results by default — in the GUI, if the user attached
        // a file they want to see everything it contained.
        var eventRows = allEvents.Select(ev => TimelineRow.ForEvent(ev, baseTs));

        var merged = packetRows.Concat(eventRows)
            .OrderBy(r => r.Timestamp)
            .ToList();

        string text = QuickSearch?.Trim() ?? "";
        IReadOnlyList<TimelineRow> filtered = text.Length == 0
            ? merged
            : merged.Where(r =>
                r.Source.Contains(text, Ci) ||
                r.Destination.Contains(text, Ci) ||
                r.Protocol.Contains(text, Ci) ||
                r.Info.Contains(text, Ci) ||
                r.NumberDisplay.Contains(text, Ci)).ToList();

        Timeline = filtered;

        int packetCount = _basePackets.Count;
        int eventCount = merged.Count - packetCount;
        if (packetCount == 0 && eventCount == 0)
        {
            ResultInfo = "";
        }
        else if (eventCount == 0)
        {
            ResultInfo = $"Showing {filtered.Count:N0} of {packetCount:N0}";
        }
        else
        {
            ResultInfo = $"Showing {filtered.Count:N0} of {packetCount:N0} packets + {eventCount:N0} events";
        }
    }

    /// <summary>Runs the Wireshark display filter through tshark and replaces the base packet set.</summary>
    [RelayCommand]
    private async Task ApplyFilterAsync()
    {
        var document = PcapSession.Current.Document;
        if (document is null)
        {
            StatusText = "Open a capture first.";
            return;
        }

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
        {
            StatusText = "tshark (Wireshark) was not found — install Wireshark to use display filters.";
            return;
        }

        IsBusy = true;
        StatusText = string.IsNullOrWhiteSpace(DisplayFilter)
            ? "Clearing display filter…"
            : $"Applying display filter: {DisplayFilter}";
        try
        {
            var matches = await tshark.SearchAsync(document.FilePath, DisplayFilter);
            _basePackets = matches;
            RebuildTimeline();
            StatusText = $"Display filter matched {matches.Count:N0} packet(s).";
        }
        catch (Exception ex)
        {
            StatusText = $"Filter error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Drops the display filter and restores the full native packet list.</summary>
    [RelayCommand]
    private void ClearFilter()
    {
        DisplayFilter = "";
        _basePackets = PcapSession.Current.Document?.Packets ?? Array.Empty<PacketSummary>();
        RebuildTimeline();
        StatusText = "Display filter cleared.";
    }
}
