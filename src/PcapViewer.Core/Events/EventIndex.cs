namespace PcapViewer.Core.Events;

/// <summary>
/// Combined, timestamp-sorted index of events drawn from every attached .evtx / .etl file.
/// Provides simple search, level/source filtering, and time-range queries.
/// </summary>
public sealed class EventIndex
{
    private const StringComparison Ci = StringComparison.OrdinalIgnoreCase;

    private readonly List<EventEntry> _events = new();

    public int Count => _events.Count;
    public IReadOnlyList<EventEntry> All => _events;

    public void AddRange(IEnumerable<EventEntry> events)
    {
        _events.AddRange(events);
        _events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
    }

    public void RemoveByAttachment(string attachmentFile)
        => _events.RemoveAll(e =>
            string.Equals(e.AttachmentFile, attachmentFile, StringComparison.OrdinalIgnoreCase));

    public void Clear() => _events.Clear();

    /// <summary>
    /// Search the index. All parameters are optional; defaults return network-relevant events only.
    /// </summary>
    public IEnumerable<EventEntry> Search(
        string? query = null,
        string? providerOrChannel = null,
        string? level = null,
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        bool networkOnly = true)
    {
        IEnumerable<EventEntry> q = _events;

        if (networkOnly)
            q = q.Where(e => e.IsNetwork);
        if (from.HasValue)
            q = q.Where(e => e.Timestamp >= from.Value);
        if (to.HasValue)
            q = q.Where(e => e.Timestamp <= to.Value);
        if (!string.IsNullOrWhiteSpace(level))
            q = q.Where(e => e.Level.Equals(level, Ci));
        if (!string.IsNullOrWhiteSpace(providerOrChannel))
            q = q.Where(e =>
                e.Provider.Contains(providerOrChannel, Ci) ||
                e.Channel.Contains(providerOrChannel, Ci));
        if (!string.IsNullOrWhiteSpace(query))
            q = q.Where(e =>
                e.Message.Contains(query, Ci) ||
                e.Provider.Contains(query, Ci) ||
                e.Channel.Contains(query, Ci) ||
                e.EventId.ToString().Contains(query));

        return q;
    }

    /// <summary>Returns events within a time window centered on <paramref name="around"/>.</summary>
    public IEnumerable<EventEntry> InWindow(DateTimeOffset around, TimeSpan before, TimeSpan after, bool networkOnly = true)
        => Search(from: around - before, to: around + after, networkOnly: networkOnly);
}
