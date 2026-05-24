using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using PcapViewer.Mcp;
using Windows.ApplicationModel.DataTransfer;

namespace PcapViewer.App;

/// <summary>Modal dialog shown after the embedded MCP server starts: URL + paste-ready client configs.</summary>
public sealed partial class McpConfigDialog : ContentDialog
{
    private readonly string _url;
    private readonly string _configUrl;

    public McpConfigDialog(string serverUrl, string configUrl)
    {
        InitializeComponent();
        _url = (serverUrl ?? "").TrimEnd('/');
        _configUrl = string.IsNullOrWhiteSpace(configUrl) ? _url + "/config" : configUrl;

        UrlBox.Text = _url;
        ClaudeCodeBox.Text   = McpClientConfig.ClaudeCodeCommand(_url);
        ClaudeDesktopBox.Text = NormalizeLines(McpClientConfig.ClaudeDesktopConfig(_url));
        VsCodeBox.Text       = NormalizeLines(McpClientConfig.VsCodeConfig(_url));
    }

    private void OnCopyUrl(object sender, RoutedEventArgs e)            => Copy(_url);
    private void OnCopyClaudeCode(object sender, RoutedEventArgs e)     => Copy(ClaudeCodeBox.Text);
    private void OnCopyClaudeDesktop(object sender, RoutedEventArgs e)  => Copy(ClaudeDesktopBox.Text);
    private void OnCopyVsCode(object sender, RoutedEventArgs e)         => Copy(VsCodeBox.Text);

    private void OnOpenBrowser(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(_configUrl) { UseShellExecute = true });
        }
        catch
        {
            // Browser open is best-effort; user can still copy the URL.
        }
    }

    private static void Copy(string text)
    {
        var package = new DataPackage();
        package.SetText(text ?? string.Empty);
        Clipboard.SetContent(package);
    }

    /// <summary>Normalize newlines to CRLF so the TextBox renders multi-line JSON cleanly.</summary>
    private static string NormalizeLines(string s)
        => s.Replace("\r\n", "\n").Replace("\n", "\r\n");
}
