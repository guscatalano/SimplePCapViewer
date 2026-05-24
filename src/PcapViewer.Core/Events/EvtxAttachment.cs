using System.Diagnostics.Eventing.Reader;
using System.Text;

namespace PcapViewer.Core.Events;

/// <summary>Reads a Windows Event Log file (.evtx) using the built-in EventLogReader.</summary>
public sealed class EvtxAttachment : EventAttachment
{
    public EvtxAttachment(string filePath) : base(filePath, kind: "evtx") { }

    public override Task LoadAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Events = ReadAll(FilePath, cancellationToken), cancellationToken);
    }

    private static List<EventEntry> ReadAll(string path, CancellationToken ct)
    {
        var list = new List<EventEntry>(capacity: 1024);
        var query = new EventLogQuery(path, PathType.FilePath);
        using var reader = new EventLogReader(query);

        for (var record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
        {
            ct.ThrowIfCancellationRequested();
            using (record)
            {
                var ts = record.TimeCreated;
                if (ts is null)
                    continue;

                string provider = record.ProviderName ?? "";
                string channel = record.LogName ?? "";
                string level = SafeLevel(record);
                string message = SafeMessage(record);

                list.Add(new EventEntry
                {
                    Timestamp = new DateTimeOffset(ts.Value.ToUniversalTime(), TimeSpan.Zero),
                    Source = "evtx",
                    Provider = provider,
                    Channel = channel,
                    EventId = record.Id,
                    Level = level,
                    ProcessId = record.ProcessId,
                    Message = message,
                    AttachmentFile = path,
                    IsNetwork = NetworkProviders.IsNetwork(provider, channel),
                });
            }
        }
        return list;
    }

    private static string SafeLevel(EventRecord record)
    {
        try { return record.LevelDisplayName ?? StandardLevel(record.Level); }
        catch { return StandardLevel(record.Level); }
    }

    private static string StandardLevel(byte? level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "",
    };

    private static string SafeMessage(EventRecord record)
    {
        // FormatDescription returns null when the publisher manifest isn't registered on this
        // machine (common when the .evtx came from another box). Fall back to a tidy dump of
        // the event's properties.
        try
        {
            string? formatted = record.FormatDescription();
            if (!string.IsNullOrWhiteSpace(formatted))
                return formatted.Trim();
        }
        catch { /* fall through */ }

        try
        {
            var props = record.Properties;
            if (props is null || props.Count == 0)
                return "";
            var sb = new StringBuilder();
            for (int i = 0; i < props.Count; i++)
            {
                if (i > 0) sb.Append("  ");
                sb.Append(props[i]?.Value?.ToString() ?? "");
            }
            return sb.ToString();
        }
        catch
        {
            return "";
        }
    }
}
