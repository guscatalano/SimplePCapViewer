using System.Net;
using System.Text;

namespace PcapViewer.Mcp;

/// <summary>
/// Generates ready-to-paste MCP client configuration for connecting to this server.
/// Surfaced on the console at startup and over HTTP at <c>/config</c>.
/// </summary>
public static class McpClientConfig
{
    /// <summary>Name the server is registered under in client configuration.</summary>
    public const string ServerName = "pcap";

    /// <summary>The <c>claude mcp add</c> command for Claude Code.</summary>
    public static string ClaudeCodeCommand(string serverUrl)
        => $"claude mcp add --transport http {ServerName} {Normalize(serverUrl)}";

    /// <summary>The block to add to Claude Desktop's claude_desktop_config.json.</summary>
    public static string ClaudeDesktopConfig(string serverUrl) => $$"""
{
  "mcpServers": {
    "{{ServerName}}": {
      "url": "{{Normalize(serverUrl)}}"
    }
  }
}
""";

    /// <summary>The block to add to VS Code's .vscode/mcp.json.</summary>
    public static string VsCodeConfig(string serverUrl) => $$"""
{
  "servers": {
    "{{ServerName}}": {
      "type": "http",
      "url": "{{Normalize(serverUrl)}}"
    }
  }
}
""";

    /// <summary>Plain-text setup instructions, for console output.</summary>
    public static string AsText(string serverUrl)
    {
        string url = Normalize(serverUrl);
        var sb = new StringBuilder();
        sb.AppendLine("Connect an MCP client to this server:");
        sb.AppendLine();
        sb.AppendLine("  Claude Code:");
        sb.AppendLine($"    {ClaudeCodeCommand(url)}");
        sb.AppendLine();
        sb.AppendLine("  Claude Desktop  —  claude_desktop_config.json:");
        sb.AppendLine(Indent(ClaudeDesktopConfig(url), "    "));
        sb.AppendLine("  VS Code  —  .vscode/mcp.json:");
        sb.AppendLine(Indent(VsCodeConfig(url), "    "));
        sb.AppendLine($"  Or open this in a browser:  {url}/config");
        return sb.ToString();
    }

    /// <summary>A self-contained HTML setup page, served from the <c>/config</c> endpoint.</summary>
    public static string AsHtml(string serverUrl)
    {
        string url = Normalize(serverUrl);
        string code = WebUtility.HtmlEncode(ClaudeCodeCommand(url));
        string desktop = WebUtility.HtmlEncode(ClaudeDesktopConfig(url));
        string vscode = WebUtility.HtmlEncode(VsCodeConfig(url));
        return $$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SimplePCapViewer — MCP server</title>
<style>
body { font-family: 'Segoe UI', system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 20px; color: #1b1b1b; line-height: 1.5; }
h1 { font-size: 20px; }
h2 { font-size: 13px; letter-spacing: .04em; margin-top: 28px; color: #555; }
pre { background: #f5f5f5; border: 1px solid #e2e2e2; border-radius: 6px; padding: 12px 14px; overflow-x: auto; }
code { background: #f5f5f5; padding: 1px 5px; border-radius: 3px; }
</style>
</head>
<body>
<h1>SimplePCapViewer — MCP server</h1>
<p>This server exposes the open packet capture to MCP clients at <code>{{url}}</code>.</p>
<h2>CLAUDE CODE</h2>
<pre>{{code}}</pre>
<h2>CLAUDE DESKTOP — claude_desktop_config.json</h2>
<pre>{{desktop}}</pre>
<h2>VS CODE — .vscode/mcp.json</h2>
<pre>{{vscode}}</pre>
</body>
</html>
""";
    }

    private static string Normalize(string serverUrl)
        => serverUrl.TrimEnd('/');

    private static string Indent(string text, string prefix)
        => string.Join('\n', text.Split('\n').Select(line => prefix + line));
}
