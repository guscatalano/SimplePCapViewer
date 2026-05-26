using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using PcapViewer.Core;
using PcapViewer.Core.Events;
using Windows.ApplicationModel.DataTransfer;

namespace PcapViewer.App;

/// <summary>
/// Dialog shown when the user clicks "Attach…": copy-paste capture commands for
/// the most useful .etl / .evtx sources, plus a Browse button to pick the file.
/// </summary>
public sealed partial class AttachInstructionsDialog : ContentDialog
{
    private const string NetshCmd =
        "netsh trace start scenario=netconnection capture=yes report=disabled tracefile=trace.etl\r\n" +
        ":: ... reproduce the issue ...\r\n" +
        "netsh trace stop";

    private const string LogmanCmd =
        "logman create trace pcap-companion -ow -o trace.etl -ets ^\r\n" +
        "    -p Microsoft-Windows-TCPIP ^\r\n" +
        "    -p Microsoft-Windows-Winsock-AFD ^\r\n" +
        "    -p Microsoft-Windows-DNS-Client ^\r\n" +
        "    -p Microsoft-Windows-Schannel-Events ^\r\n" +
        "    -p Microsoft-Windows-WFP\r\n" +
        ":: ... reproduce ...\r\n" +
        "logman stop pcap-companion -ets";

    private const string SchannelCmd =
        "wevtutil epl System schannel.evtx /q:\"*[System/Provider/@Name='Schannel']\"";

    private const string DnsCmd =
        "wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true\r\n" +
        "wevtutil epl Microsoft-Windows-DNS-Client/Operational dns.evtx";

    private const string WlanCmd =
        "wevtutil epl Microsoft-Windows-WLAN-AutoConfig/Operational wlan.evtx";

    private const string ReadmeUrl =
        "https://github.com/guscatalano/SimplePCapViewer#attaching-event-logs--etw-traces";

    public AttachInstructionsDialog()
    {
        InitializeComponent();
        NetshBox.Text    = NetshCmd;
        LogmanBox.Text   = LogmanCmd;
        SchannelBox.Text = SchannelCmd;
        DnsBox.Text      = DnsCmd;
        WlanBox.Text     = WlanCmd;
        RefreshAttachedList();
    }

    /// <summary>One row in the "Currently attached" list at the top of the dialog.</summary>
    public sealed class AttachedItem
    {
        public string FilePath { get; init; } = "";
        public string FileName { get; init; } = "";
        public string PathDisplay { get; init; } = "";
        public string EventCountLabel { get; init; } = "";
    }

    private void RefreshAttachedList()
    {
        var rows = PcapSession.Current.Attachments
            .Select(a => new AttachedItem
            {
                FilePath        = a.FilePath,
                FileName        = Path.GetFileName(a.FilePath),
                PathDisplay     = Path.GetDirectoryName(a.FilePath) ?? "",
                EventCountLabel = $"{a.Events.Count:N0} events",
            })
            .ToList();

        AttachedList.ItemsSource = rows;
        AttachedSection.Visibility = rows.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnDetachClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string path)
        {
            PcapSession.Current.Detach(path);
            RefreshAttachedList();
        }
    }

    private void OnCopyNetsh(object sender, RoutedEventArgs e)    => Copy(NetshBox.Text);
    private void OnCopyLogman(object sender, RoutedEventArgs e)   => Copy(LogmanBox.Text);
    private void OnCopySchannel(object sender, RoutedEventArgs e) => Copy(SchannelBox.Text);
    private void OnCopyDns(object sender, RoutedEventArgs e)      => Copy(DnsBox.Text);
    private void OnCopyWlan(object sender, RoutedEventArgs e)     => Copy(WlanBox.Text);

    private void OnOpenReadme(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(ReadmeUrl) { UseShellExecute = true }); }
        catch { /* best-effort */ }
    }

    private static void Copy(string text)
    {
        var package = new DataPackage();
        package.SetText(text ?? string.Empty);
        Clipboard.SetContent(package);
    }
}
