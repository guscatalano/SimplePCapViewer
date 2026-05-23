using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcapViewer.Core;
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
        Packets = Array.Empty<PacketSummary>();
        HexDump = "";
        DetailStatus = "Select a packet to see its dissection.";
        McpStatus = "MCP server: stopped";
        PortText = McpHost.DefaultPort.ToString();
    }

    [ObservableProperty] public partial string FileName { get; set; }
    [ObservableProperty] public partial string StatusText { get; set; }
    [ObservableProperty] public partial string QuickSearch { get; set; }
    [ObservableProperty] public partial string DisplayFilter { get; set; }
    [ObservableProperty] public partial string ResultInfo { get; set; }
    [ObservableProperty] public partial IReadOnlyList<PacketSummary> Packets { get; set; }
    [ObservableProperty] public partial PacketSummary? SelectedPacket { get; set; }
    [ObservableProperty] public partial string HexDump { get; set; }
    [ObservableProperty] public partial string DetailStatus { get; set; }
    [ObservableProperty] public partial string McpStatus { get; set; }
    [ObservableProperty] public partial string PortText { get; set; }
    [ObservableProperty] public partial bool IsBusy { get; set; }

    /// <summary>Loads a capture file and refreshes the packet list.</summary>
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
            ApplyQuickSearch();

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
            ApplyQuickSearch();
            StatusText = $"Failed to open file: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    partial void OnQuickSearchChanged(string value) => ApplyQuickSearch();

    private void ApplyQuickSearch()
    {
        string text = QuickSearch?.Trim() ?? "";
        Packets = text.Length == 0
            ? _basePackets
            : _basePackets.Where(p =>
                p.Source.Contains(text, Ci) ||
                p.Destination.Contains(text, Ci) ||
                p.Protocol.Contains(text, Ci) ||
                p.Info.Contains(text, Ci) ||
                p.Number.ToString().Contains(text, Ci)).ToList();

        ResultInfo = _basePackets.Count == 0
            ? ""
            : $"Showing {Packets.Count:N0} of {_basePackets.Count:N0}";
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
            ApplyQuickSearch();
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
        ApplyQuickSearch();
        StatusText = "Display filter cleared.";
    }
}
