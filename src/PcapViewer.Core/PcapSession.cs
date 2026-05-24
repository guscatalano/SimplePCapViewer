using PcapViewer.Core.Events;
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

    // ---- attached event sources (.evtx / .etl) ----------------------------

    private readonly List<EventAttachment> _attachments = new();

    /// <summary>Attached .evtx and .etl files, in attach order.</summary>
    public IReadOnlyList<EventAttachment> Attachments => _attachments;

    /// <summary>Timestamp-sorted index of events from every attached file.</summary>
    public EventIndex EventIndex { get; } = new();

    /// <summary>Raised when an attachment is added or removed.</summary>
    public event EventHandler? AttachmentsChanged;

    /// <summary>
    /// Loads an <c>.evtx</c> or <c>.etl</c> file and adds its events to <see cref="EventIndex"/>.
    /// The extension determines the reader.
    /// </summary>
    public async Task<EventAttachment> AttachAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Attachment file not found.", path);

        string ext = Path.GetExtension(path).ToLowerInvariant();
        EventAttachment attachment = ext switch
        {
            ".evtx" => new EvtxAttachment(path),
            ".etl"  => new EtlAttachment(path),
            _ => throw new NotSupportedException(
                $"Unsupported attachment type '{ext}'. Only .etl and .evtx are supported."),
        };

        await attachment.LoadAsync(cancellationToken);
        _attachments.Add(attachment);
        EventIndex.AddRange(attachment.Events);
        AttachmentsChanged?.Invoke(this, EventArgs.Empty);
        return attachment;
    }

    /// <summary>Removes the attachment at <paramref name="filePath"/> from the session.</summary>
    public bool Detach(string filePath)
    {
        var attachment = _attachments.FirstOrDefault(a =>
            string.Equals(a.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
        if (attachment is null)
            return false;
        _attachments.Remove(attachment);
        EventIndex.RemoveByAttachment(attachment.FilePath);
        AttachmentsChanged?.Invoke(this, EventArgs.Empty);
        return true;
    }

    /// <summary>Drops every attachment and clears <see cref="EventIndex"/>.</summary>
    public void ClearAttachments()
    {
        if (_attachments.Count == 0)
            return;
        _attachments.Clear();
        EventIndex.Clear();
        AttachmentsChanged?.Invoke(this, EventArgs.Empty);
    }
}
