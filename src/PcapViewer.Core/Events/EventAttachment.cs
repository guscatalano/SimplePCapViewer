namespace PcapViewer.Core.Events;

/// <summary>An .evtx or .etl file attached to the current pcap session.</summary>
public abstract class EventAttachment
{
    protected EventAttachment(string filePath, string kind)
    {
        FilePath = filePath;
        Kind = kind;
        FileName = Path.GetFileName(filePath);
    }

    public string FilePath { get; }
    public string FileName { get; }
    public string Kind { get; }
    public IReadOnlyList<EventEntry> Events { get; protected set; } = Array.Empty<EventEntry>();

    /// <summary>Parses the file off the calling thread and fills <see cref="Events"/>.</summary>
    public abstract Task LoadAsync(CancellationToken cancellationToken = default);
}
