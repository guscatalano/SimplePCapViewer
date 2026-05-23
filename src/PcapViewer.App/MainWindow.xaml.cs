using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using PcapViewer.Core;
using PcapViewer.Core.Models;
using PcapViewer.Mcp;
using Windows.Storage.Pickers;
using Windows.System;

namespace PcapViewer.App;

/// <summary>The viewer window: packet list, search, detail pane and the embedded MCP server.</summary>
public sealed partial class MainWindow : Window
{
    private readonly McpHost _mcpHost = new();

    public MainViewModel ViewModel { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        Title = "SimplePCapViewer";
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1320, 860));

        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (File.Exists(iconPath))
            AppWindow.SetIcon(iconPath);

        Closed += OnWindowClosed;
    }

    // ---- file open -------------------------------------------------------

    private async void OnOpenClick(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            ViewMode = PickerViewMode.List,
        };
        picker.FileTypeFilter.Add(".pcap");
        picker.FileTypeFilter.Add(".pcapng");
        picker.FileTypeFilter.Add(".cap");

        // Unpackaged WinUI3 apps must associate the picker with the window handle.
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

        var file = await picker.PickSingleFileAsync();
        if (file is not null)
            await ViewModel.OpenAsync(file.Path);
    }

    // ---- search ----------------------------------------------------------

    private void OnQuickSearchTextChanged(object sender, TextChangedEventArgs e)
        => ViewModel.QuickSearch = ((TextBox)sender).Text;

    private void OnDisplayFilterKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter && ViewModel.ApplyFilterCommand.CanExecute(null))
        {
            ViewModel.ApplyFilterCommand.Execute(null);
            e.Handled = true;
        }
    }

    // ---- packet detail ---------------------------------------------------

    private async void OnPacketSelectionChanged(object sender, SelectionChangedEventArgs e)
        => await LoadSelectedPacketDetailAsync();

    private async Task LoadSelectedPacketDetailAsync()
    {
        var packet = ViewModel.SelectedPacket;
        DetailTree.RootNodes.Clear();
        ViewModel.HexDump = "";

        if (packet is null)
        {
            ViewModel.DetailStatus = "Select a packet to see its dissection.";
            return;
        }

        var document = PcapSession.Current.Document;
        if (document is null)
            return;

        ViewModel.HexDump = document.GetHexDump(packet.Number);

        var tshark = PcapSession.Current.Tshark;
        if (!tshark.IsAvailable)
        {
            ViewModel.DetailStatus =
                $"Packet {packet.Number} — install Wireshark for full per-field dissection.";
            return;
        }

        ViewModel.DetailStatus = $"Dissecting packet {packet.Number}…";
        try
        {
            var detail = await tshark.GetDetailAsync(document.FilePath, packet.Number);

            // The selection may have changed while tshark was running.
            if (ViewModel.SelectedPacket?.Number != packet.Number)
                return;

            DetailTree.RootNodes.Clear();
            foreach (var proto in detail.Protocols)
                DetailTree.RootNodes.Add(BuildNode(proto));

            ViewModel.DetailStatus =
                $"Packet {packet.Number} — {detail.Protocols.Count} protocol layer(s)";
        }
        catch (Exception ex)
        {
            ViewModel.DetailStatus = $"Dissection failed: {ex.Message}";
        }
    }

    // ---- TLS decryption ---------------------------------------------------

    private async void OnTlsKeysClick(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            ViewMode = PickerViewMode.List,
        };
        picker.FileTypeFilter.Add("*");

        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

        var file = await picker.PickSingleFileAsync();
        if (file is null)
            return;

        PcapSession.Current.TlsKeyLogPath = file.Path;
        TlsButtonLabel.Text = "TLS keys ✓";
        ViewModel.StatusText =
            $"TLS key log loaded — HTTPS is now decrypted in search and dissection ({file.Path}).";

        // Re-dissect the selected packet so decryption shows immediately.
        await LoadSelectedPacketDetailAsync();
    }

    private static TreeViewNode BuildNode(PacketDetailNode source)
    {
        var node = new TreeViewNode { Content = source.Label, IsExpanded = true };
        foreach (var child in source.Children)
            node.Children.Add(BuildNode(child));
        return node;
    }

    // ---- embedded MCP server --------------------------------------------

    private async void OnMcpToggled(object sender, RoutedEventArgs e)
    {
        var toggle = (ToggleSwitch)sender;
        if (toggle.IsOn)
        {
            if (!int.TryParse(ViewModel.PortText, out var port) || port is < 1 or > 65535)
            {
                ViewModel.McpStatus = "MCP server: invalid port";
                toggle.IsOn = false;
                return;
            }
            try
            {
                await _mcpHost.StartAsync(port);
                ViewModel.McpStatus = $"MCP server: listening on {_mcpHost.Url}";
                ViewModel.StatusText =
                    $"MCP server started — connect a client to {_mcpHost.Url}  ·  " +
                    $"copy-paste setup at {_mcpHost.ConfigUrl}";
            }
            catch (Exception ex)
            {
                ViewModel.McpStatus = $"MCP server: failed to start ({ex.Message})";
                toggle.IsOn = false;
            }
        }
        else
        {
            try
            {
                await _mcpHost.StopAsync();
                ViewModel.McpStatus = "MCP server: stopped";
            }
            catch (Exception ex)
            {
                ViewModel.McpStatus = $"MCP server: error stopping ({ex.Message})";
            }
        }
    }

    private void OnWindowClosed(object sender, WindowEventArgs args)
        => _ = _mcpHost.StopAsync();
}
