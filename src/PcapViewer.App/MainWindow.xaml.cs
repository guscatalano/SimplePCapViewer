using System.Runtime.InteropServices;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using PcapViewer.Core;
using PcapViewer.Core.Models;
using PcapViewer.Mcp;
using Windows.ApplicationModel.DataTransfer;
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
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1500, 900));

        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (File.Exists(iconPath))
            AppWindow.SetIcon(iconPath);

        PcapSession.Current.AttachmentsChanged += OnAttachmentsChanged;
        Closed += OnWindowClosed;
    }

    private void OnAttachmentsChanged(object? sender, EventArgs e)
    {
        int total = PcapSession.Current.Attachments.Count;
        AttachButtonLabel.Text = total switch
        {
            0 => "Attach…",
            1 => "Attached (1)",
            _ => $"Attached ({total})",
        };
    }

    // ---- file open -------------------------------------------------------

    /// <summary>
    /// Open everything passed on the command line: the first capture (.pcap / .pcapng / .cap)
    /// becomes the active document; .evtx / .etl files are attached. Auto-selects the first row.
    /// </summary>
    public async void OpenFromCommandLineAsync(IReadOnlyList<string> paths)
    {
        string? capturePath = paths.FirstOrDefault(p =>
        {
            string ext = Path.GetExtension(p).ToLowerInvariant();
            return ext is ".pcap" or ".pcapng" or ".cap";
        });

        if (capturePath is not null)
            await ViewModel.OpenAsync(capturePath);

        foreach (var p in paths)
        {
            string ext = Path.GetExtension(p).ToLowerInvariant();
            if (ext is ".evtx" or ".etl")
            {
                try { await PcapSession.Current.AttachAsync(p); }
                catch (Exception ex) { ViewModel.StatusText = $"Attach failed for {Path.GetFileName(p)}: {ex.Message}"; }
            }
        }

        if (ViewModel.Timeline.Count > 0)
            ViewModel.SelectedRow = ViewModel.Timeline[0];
    }

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
        => await LoadSelectedRowDetailAsync();

    private async Task LoadSelectedRowDetailAsync()
    {
        var row = ViewModel.SelectedRow;
        DetailTree.RootNodes.Clear();
        ViewModel.HexDump = "";

        if (row is null)
        {
            ViewModel.DetailStatus = "Select a packet to see its dissection.";
            return;
        }

        if (row.IsEvent && row.Event is not null)
        {
            ShowEventDetail(row.Event);
            return;
        }

        var packet = row.Packet;
        if (packet is null)
            return;

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
            if (ViewModel.SelectedRow?.Packet?.Number != packet.Number)
                return;

            DetailTree.RootNodes.Clear();
            foreach (var proto in detail.Protocols)
            {
                // Default-collapse the verbose meta layers ("General information" and
                // "Frame N: …") so the actual protocol stack is visible without scrolling.
                bool collapseRoot = proto.Label.StartsWith("General ", StringComparison.OrdinalIgnoreCase)
                                 || proto.Label.StartsWith("Frame ",   StringComparison.OrdinalIgnoreCase);
                DetailTree.RootNodes.Add(BuildNode(proto, isRootExpanded: !collapseRoot));
            }

            ViewModel.DetailStatus =
                $"Packet {packet.Number} — {detail.Protocols.Count} protocol layer(s)";
        }
        catch (Exception ex)
        {
            ViewModel.DetailStatus = $"Dissection failed: {ex.Message}";
        }
    }

    /// <summary>Render an attached event in the dissection pane (no tshark involved).</summary>
    private void ShowEventDetail(PcapViewer.Core.Events.EventEntry ev)
    {
        var root = new TreeViewNode
        {
            Content = $"Event {ev.EventId} — {ev.Provider}",
            IsExpanded = true,
        };
        root.Children.Add(new TreeViewNode { Content = $"Timestamp: {ev.Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}" });
        root.Children.Add(new TreeViewNode { Content = $"Level: {ev.Level}" });
        root.Children.Add(new TreeViewNode { Content = $"Provider: {ev.Provider}" });
        if (!string.IsNullOrEmpty(ev.Channel))
            root.Children.Add(new TreeViewNode { Content = $"Channel: {ev.Channel}" });
        root.Children.Add(new TreeViewNode { Content = $"Event ID: {ev.EventId}" });
        if (ev.ProcessId.HasValue)
            root.Children.Add(new TreeViewNode { Content = $"Process ID: {ev.ProcessId.Value}" });
        root.Children.Add(new TreeViewNode { Content = $"Source: .{ev.Source}  ({Path.GetFileName(ev.AttachmentFile)})" });

        var message = new TreeViewNode { Content = "Message", IsExpanded = true };
        foreach (var line in (ev.Message ?? "").Split('\n'))
            message.Children.Add(new TreeViewNode { Content = line.TrimEnd('\r') });
        root.Children.Add(message);

        DetailTree.RootNodes.Add(root);
        ViewModel.DetailStatus = $"Event #{ev.EventId} — {ev.Provider} — attached from {Path.GetFileName(ev.AttachmentFile)}";
        ViewModel.HexDump = "";
    }

    // ---- attach .evtx / .etl ---------------------------------------------

    private async void OnAttachClick(object sender, RoutedEventArgs e)
    {
        // Show the capture-instructions dialog first; the user can copy commands
        // and then click "Browse…" to actually pick the file.
        var instructions = new AttachInstructionsDialog { XamlRoot = Content.XamlRoot };
        var result = await instructions.ShowAsync();
        if (result != ContentDialogResult.Primary)
            return;

        // WinRT FileOpenPicker silently fails to appear when shown right after a
        // ContentDialog closes in unpackaged WinUI 3. The classic Win32 picker is
        // synchronous and always shows, so we use that here.
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        string filter =
            "Event log / ETW trace (*.evtx;*.etl)\0*.evtx;*.etl\0" +
            "Windows event log (*.evtx)\0*.evtx\0" +
            "ETW trace (*.etl)\0*.etl\0" +
            "All files (*.*)\0*.*\0";

        string? path = Win32FilePicker.PickSingleFile(hwnd,
            title: "Attach event log or ETW trace",
            filter: filter);

        if (path is null)
        {
            ViewModel.StatusText = "Attach cancelled.";
            return;
        }

        string fileName = Path.GetFileName(path);
        ViewModel.StatusText = $"Loading {fileName}…";
        try
        {
            var attachment = await PcapSession.Current.AttachAsync(path);
            int network = attachment.Events.Count(ev => ev.IsNetwork);
            // AttachButtonLabel is updated by OnAttachmentsChanged.
            ViewModel.StatusText =
                $"Attached {fileName}: {attachment.Events.Count:N0} events " +
                $"({network:N0} network-related). " +
                $"Total across attachments: {PcapSession.Current.EventIndex.Count:N0} events.";
        }
        catch (Exception ex)
        {
            ViewModel.StatusText = $"Attach failed: {ex.Message}";
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
        await LoadSelectedRowDetailAsync();
    }

    private static TreeViewNode BuildNode(PacketDetailNode source, bool isRootExpanded = true)
    {
        var node = new TreeViewNode { Content = source.Label, IsExpanded = isRootExpanded };
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
                    $"MCP server started — click the URL above for client setup, " +
                    $"or open {_mcpHost.ConfigUrl} in a browser.";
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

    /// <summary>Show the MCP client-config dialog when the user clicks the running URL.</summary>
    private async void OnMcpStatusClick(object sender, RoutedEventArgs e)
    {
        if (!_mcpHost.IsRunning)
            return;
        var dialog = new McpConfigDialog(_mcpHost.Url, _mcpHost.ConfigUrl)
        {
            XamlRoot = Content.XamlRoot,
        };
        await dialog.ShowAsync();
    }

    // ---- right-click copy -----------------------------------------------

    private void OnCopyPacketRow(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TimelineRow r)
            SetClipboard($"{r.NumberDisplay}\t{r.TimeDisplay}\t{r.Source}\t{r.Destination}\t" +
                         $"{r.Protocol}\t{r.LengthDisplay}\t{r.Info}");
    }

    private void OnCopyPacketSource(object sender, RoutedEventArgs e)
        => CopyRowField(sender, r => r.Source);

    private void OnCopyPacketDestination(object sender, RoutedEventArgs e)
        => CopyRowField(sender, r => r.Destination);

    private void OnCopyPacketProtocol(object sender, RoutedEventArgs e)
        => CopyRowField(sender, r => r.Protocol);

    private void OnCopyPacketInfo(object sender, RoutedEventArgs e)
        => CopyRowField(sender, r => r.Info);

    private void OnCopyDetailSubtree(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TreeViewNode node)
        {
            var sb = new StringBuilder();
            AppendSubtree(node, depth: 0, sb);
            SetClipboard(sb.ToString().TrimEnd());
        }
    }

    private void OnCopyDetailLine(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is TreeViewNode node)
            SetClipboard(node.Content?.ToString() ?? string.Empty);
    }

    private static void AppendSubtree(TreeViewNode node, int depth, StringBuilder sb)
    {
        sb.Append(' ', depth * 2);
        sb.AppendLine(node.Content?.ToString() ?? string.Empty);
        foreach (var child in node.Children)
            AppendSubtree(child, depth + 1, sb);
    }

    private static void CopyRowField(object sender, Func<TimelineRow, string> selector)
    {
        if ((sender as FrameworkElement)?.DataContext is TimelineRow r)
            SetClipboard(selector(r));
    }

    private static void SetClipboard(string text)
    {
        var package = new DataPackage();
        package.SetText(text ?? string.Empty);
        Clipboard.SetContent(package);
    }
}
