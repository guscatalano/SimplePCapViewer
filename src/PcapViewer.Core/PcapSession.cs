using PcapViewer.Core.Tshark;

namespace PcapViewer.Core;

/// <summary>
/// Process-wide shared state: the capture currently open in the viewer.
/// The WinUI viewer writes it when the user opens a file; the embedded MCP server
/// reads it so that MCP tools always operate on whatever the user is looking at.
/// </summary>
public sealed class PcapSession
{
    /// <summary>The single shared session for this process.</summary>
    public static PcapSession Current { get; } = new();

    private PcapSession() => Tshark = new TsharkService();

    /// <summary>Shared tshark wrapper (search, dissection, statistics).</summary>
    public TsharkService Tshark { get; }

    /// <summary>
    /// TLS key log file (an <c>SSLKEYLOGFILE</c>) used to decrypt HTTPS in every tshark
    /// operation. Set it to turn decryption on; null/empty turns it off.
    /// </summary>
    public string? TlsKeyLogPath
    {
        get => Tshark.TlsKeyLogFile;
        set => Tshark.TlsKeyLogFile = string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>The capture currently open, or null if none. Reference assignment is atomic.</summary>
    public PcapDocument? Document { get; private set; }

    /// <summary>Raised on the thread that opened/closed the document.</summary>
    public event EventHandler? DocumentChanged;

    public async Task<PcapDocument> OpenAsync(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Capture file not found.", path);

        var document = await Task.Run(() => PcapDocument.Load(path));
        Document = document;
        DocumentChanged?.Invoke(this, EventArgs.Empty);
        return document;
    }

    public void Close()
    {
        Document = null;
        DocumentChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Returns the open document or throws a message suitable for surfacing to an MCP client.</summary>
    public PcapDocument RequireDocument()
        => Document ?? throw new InvalidOperationException(
            "No capture is open. Open a .pcap or .pcapng file in the SimplePCapViewer window first.");
}
