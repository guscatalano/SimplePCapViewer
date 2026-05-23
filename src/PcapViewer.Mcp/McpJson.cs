using System.Text.Json;
using System.Text.Json.Serialization;

namespace PcapViewer.Mcp;

/// <summary>Shared JSON serialization settings for MCP tool results.</summary>
internal static class McpJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    /// <summary>Result returned when no capture is open in the viewer.</summary>
    public static string NoCapture() => Serialize(new
    {
        error = "no_capture_open",
        message = "No capture is open. Ask the user to open a .pcap or .pcapng file " +
                  "in the SimplePCapViewer window, then retry.",
    });

    /// <summary>Result returned when an operation fails.</summary>
    public static string Failure(string message) => Serialize(new
    {
        error = "operation_failed",
        message,
    });
}
