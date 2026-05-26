using System.Globalization;
using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using PcapViewer.Core.Events;
using PcapViewer.Core.Models;
using Windows.UI;
using Windows.UI.Text;

namespace PcapViewer.App;

/// <summary>
/// A unified row for the main list: either a captured packet or an attached event.
/// Events are interleaved chronologically with packets so that the timeline shows
/// both wire activity and the OS-side context (DNS, TLS, Wi-Fi, firewall, …) for it.
/// </summary>
public sealed class TimelineRow
{
    public bool IsEvent { get; init; }
    public PacketSummary? Packet { get; init; }
    public EventEntry? Event { get; init; }

    public DateTimeOffset Timestamp { get; init; }

    // Display fields — bound directly by the ListView template.
    public string NumberDisplay { get; init; } = "";
    public string TimeDisplay { get; init; } = "";
    public string Source { get; init; } = "";
    public string Destination { get; init; } = "";
    public string Protocol { get; init; } = "";
    public string LengthDisplay { get; init; } = "";
    public string Info { get; init; } = "";

    // ---- visual differentiation (bound via x:Bind in MainWindow.xaml) ----

    // Cached at first use; brushes must be created on the UI thread.
    private static SolidColorBrush? _eventRowBrush;
    private static SolidColorBrush EventRowBrush()
        => _eventRowBrush ??= new SolidColorBrush(Color.FromArgb(38, 255, 185, 0));   // soft amber

    private static SolidColorBrush? _eventAccentBrush;
    private static SolidColorBrush EventAccentBrush()
        => _eventAccentBrush ??= new SolidColorBrush(Color.FromArgb(255, 224, 142, 0));

    private static Brush? _secondaryTextBrush;
    private static Brush SecondaryTextBrush()
        => _secondaryTextBrush ??= (Brush)Microsoft.UI.Xaml.Application.Current.Resources["TextFillColorSecondaryBrush"];

    private static Brush? _primaryTextBrush;
    private static Brush PrimaryTextBrush()
        => _primaryTextBrush ??= (Brush)Microsoft.UI.Xaml.Application.Current.Resources["TextFillColorPrimaryBrush"];

    /// <summary>Row background — amber tint for events, transparent for packets.</summary>
    public Brush RowBackground => IsEvent ? EventRowBrush() : new SolidColorBrush(Colors.Transparent);

    /// <summary>Italic for events, normal for packets.</summary>
    public FontStyle RowFontStyle => IsEvent ? FontStyle.Italic : FontStyle.Normal;

    /// <summary>Number column: secondary (grey) for packets, accent for events.</summary>
    public Brush NumberForeground => IsEvent ? EventAccentBrush() : SecondaryTextBrush();

    /// <summary>Protocol column: primary for packets, accent for events.</summary>
    public Brush ProtocolForeground => IsEvent ? EventAccentBrush() : PrimaryTextBrush();

    public static TimelineRow ForPacket(PacketSummary packet) => new()
    {
        IsEvent = false,
        Packet = packet,
        Timestamp = packet.Timestamp,
        NumberDisplay = packet.Number.ToString(CultureInfo.InvariantCulture),
        TimeDisplay = packet.TimeDisplay,
        Source = packet.Source,
        Destination = packet.Destination,
        Protocol = packet.Protocol,
        LengthDisplay = packet.Length.ToString(CultureInfo.InvariantCulture),
        Info = packet.Info,
    };

    public static TimelineRow ForEvent(EventEntry ev, DateTimeOffset baseTimestamp)
    {
        // Strip the long "Microsoft-Windows-" prefix so the column stays readable.
        string provider = ev.Provider;
        if (provider.StartsWith("Microsoft-Windows-", StringComparison.Ordinal))
            provider = provider.Substring("Microsoft-Windows-".Length);

        double offset = (ev.Timestamp - baseTimestamp).TotalSeconds;

        return new TimelineRow
        {
            IsEvent = true,
            Event = ev,
            Timestamp = ev.Timestamp,
            NumberDisplay = "·",                    // small marker instead of a packet number
            TimeDisplay = offset.ToString("0.000000", CultureInfo.InvariantCulture),
            Source = provider,
            Destination = string.IsNullOrEmpty(ev.Channel) ? ev.Source.ToUpperInvariant() : ev.Channel,
            Protocol = "EVENT",
            LengthDisplay = $"#{ev.EventId}",
            Info = $"[{ev.Level}] {ev.Message}",
        };
    }
}
