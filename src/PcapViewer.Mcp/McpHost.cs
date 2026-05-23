using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace PcapViewer.Mcp;

/// <summary>
/// Hosts the MCP server over HTTP, in-process inside the WinUI viewer.
/// The server exposes whatever capture is currently open via <see cref="PcapMcpTools"/>.
/// </summary>
public sealed class McpHost
{
    public const int DefaultPort = 7777;

    private WebApplication? _app;

    public bool IsRunning => _app is not null;

    public int Port { get; private set; }

    /// <summary>The base URL an MCP client should connect to.</summary>
    public string Url => $"http://127.0.0.1:{Port}/";

    /// <summary>A browser-friendly page with ready-to-paste MCP client configuration.</summary>
    public string ConfigUrl => $"http://127.0.0.1:{Port}/config";

    /// <summary>Starts the HTTP MCP server. Safe to call again while already running (no-op).</summary>
    public async Task StartAsync(int port = DefaultPort, CancellationToken cancellationToken = default)
    {
        if (_app is not null)
            return;

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        builder.Services
            .AddMcpServer(options =>
            {
                options.ServerInfo = new() { Name = "SimplePCapViewer", Version = "1.0.0" };
            })
            .WithHttpTransport()
            .WithTools<PcapMcpTools>();

        var app = builder.Build();
        app.Urls.Clear();
        app.Urls.Add($"http://127.0.0.1:{port}");
        app.MapMcp();

        // Expose ready-to-paste client configuration at /config.
        app.MapGet("/config", () => Results.Content(
            McpClientConfig.AsHtml($"http://127.0.0.1:{port}"), "text/html; charset=utf-8"));

        await app.StartAsync(cancellationToken);
        _app = app;
        Port = port;
    }

    /// <summary>Stops the server. Safe to call when not running (no-op).</summary>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        var app = _app;
        if (app is null)
            return;

        _app = null;
        await app.StopAsync(cancellationToken);
        await app.DisposeAsync();
    }
}
