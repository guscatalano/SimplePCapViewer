using PcapViewer.Core;
using PcapViewer.Mcp;

// Standalone entry point for the MCP server.
//
//   PcapViewer.Mcp <capture.pcap|.pcapng> [--port <n>]
//
// The exact same MCP server (McpHost + PcapMcpTools) is also hosted in-process by
// the SimplePCapViewer WinUI app, where it exposes whatever capture is open in the
// viewer. This standalone host exposes a single capture passed on the command line.

int port = McpHost.DefaultPort;
string? capturePath = null;
string? tlsKeyLog = null;

for (int i = 0; i < args.Length; i++)
{
    if ((args[i] is "--port" or "-p") && i + 1 < args.Length && int.TryParse(args[i + 1], out int p))
    {
        port = p;
        i++;
    }
    else if (args[i] is "--tls-keylog" && i + 1 < args.Length)
    {
        tlsKeyLog = args[i + 1];
        i++;
    }
    else if (!args[i].StartsWith('-'))
    {
        capturePath = args[i];
    }
}

if (capturePath is null)
{
    Console.Error.WriteLine("Usage: PcapViewer.Mcp <capture.pcap|.pcapng> [--port <n>] [--tls-keylog <file>]");
    return 1;
}

try
{
    Console.WriteLine($"Loading capture: {capturePath}");
    var document = await PcapSession.Current.OpenAsync(capturePath);
    Console.WriteLine($"Loaded {document.Info.PacketCount:N0} packets " +
                      $"({document.Info.FileFormat}, {document.Info.LinkType}).");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to open capture: {ex.Message}");
    return 1;
}

if (tlsKeyLog is not null)
{
    if (File.Exists(tlsKeyLog))
    {
        PcapSession.Current.TlsKeyLogPath = tlsKeyLog;
        Console.WriteLine($"TLS decryption enabled (key log: {tlsKeyLog}).");
    }
    else
    {
        Console.Error.WriteLine($"Warning: TLS key log not found — decryption disabled: {tlsKeyLog}");
    }
}

var host = new McpHost();
try
{
    await host.StartAsync(port);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to start MCP server: {ex.Message}");
    return 1;
}

Console.WriteLine($"MCP server listening at {host.Url}");
Console.WriteLine($"tshark available: {PcapSession.Current.Tshark.IsAvailable}");
Console.WriteLine();
Console.WriteLine(McpClientConfig.AsText(host.Url));
Console.WriteLine("Press Ctrl+C to stop.");

var shutdown = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    shutdown.TrySetResult();
};
await shutdown.Task;

Console.WriteLine("Stopping…");
await host.StopAsync();
return 0;
