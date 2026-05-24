using Microsoft.Diagnostics.Tracing;

namespace PcapViewer.Core.Events;

/// <summary>Reads an ETW trace file (.etl) using Microsoft.Diagnostics.Tracing.TraceEvent.</summary>
public sealed class EtlAttachment : EventAttachment
{
    public EtlAttachment(string filePath) : base(filePath, kind: "etl") { }

    public override Task LoadAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Events = ReadAll(FilePath, cancellationToken), cancellationToken);
    }

    private static List<EventEntry> ReadAll(string path, CancellationToken ct)
    {
        var list = new List<EventEntry>(capacity: 8192);

        using var source = new ETWTraceEventSource(path);
        source.AllEvents += evt =>
        {
            if (ct.IsCancellationRequested)
            {
                source.StopProcessing();
                return;
            }

            // Skip ETW manifest / metadata events.
            if (evt.IsClassicProvider == false && evt.ID == 0 && string.IsNullOrEmpty(evt.EventName))
                return;

            string provider = evt.ProviderName ?? "";
            string message = BuildMessage(evt);

            list.Add(new EventEntry
            {
                Timestamp = new DateTimeOffset(evt.TimeStamp.ToUniversalTime(), TimeSpan.Zero),
                Source = "etl",
                Provider = provider,
                Channel = "",
                EventId = (int)evt.ID,
                Level = LevelString(evt.Level),
                ProcessId = evt.ProcessID >= 0 ? evt.ProcessID : null,
                Message = (message ?? "").Trim(),
                AttachmentFile = path,
                IsNetwork = NetworkProviders.IsNetwork(provider, channel: ""),
            });
        };

        source.Process();
        return list;
    }

    private static string BuildMessage(TraceEvent evt)
    {
        try
        {
            string? formatted = evt.FormattedMessage;
            if (!string.IsNullOrWhiteSpace(formatted))
                return formatted.Trim();
        }
        catch { /* fall through */ }

        string name = evt.EventName ?? "";
        string[]? names = evt.PayloadNames;
        if (names is null || names.Length == 0)
            return name;

        var parts = new List<string>(names.Length);
        for (int i = 0; i < names.Length; i++)
        {
            string val;
            try { val = evt.PayloadString(i) ?? ""; }
            catch { val = ""; }
            if (val.Length > 0)
                parts.Add($"{names[i]}={val}");
        }
        return parts.Count == 0 ? name : (name.Length == 0 ? string.Join("  ", parts) : $"{name}  {string.Join("  ", parts)}");
    }

    private static string LevelString(TraceEventLevel level) => level switch
    {
        TraceEventLevel.Critical => "Critical",
        TraceEventLevel.Error => "Error",
        TraceEventLevel.Warning => "Warning",
        TraceEventLevel.Informational => "Information",
        TraceEventLevel.Verbose => "Verbose",
        _ => level.ToString(),
    };

    /// <summary>True if a string looks like an extension that <see cref="EtlAttachment"/> can read.</summary>
    public static bool IsSupportedExtension(string path)
        => string.Equals(Path.GetExtension(path), ".etl", StringComparison.OrdinalIgnoreCase);
}
