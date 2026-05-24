using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using PcapViewer.Core.Models;

namespace PcapViewer.Core.Tshark;

/// <summary>
/// Wraps the Wireshark <c>tshark</c> CLI for the things a pure-managed parser cannot do well:
/// display-filter search, full per-field dissection, conversation/protocol statistics,
/// stream reassembly and object extraction.
/// </summary>
public sealed partial class TsharkService
{
    private static readonly string[] SearchFields =
    {
        "frame.number", "frame.time_epoch", "frame.time_relative",
        "_ws.col.Source", "_ws.col.Destination", "_ws.col.Protocol",
        "frame.len", "_ws.col.Info",
    };

    public TsharkService(string? explicitPath = null)
        => TsharkPath = explicitPath is not null && File.Exists(explicitPath)
            ? explicitPath
            : Locate();

    /// <summary>Resolved path to tshark.exe, or null if Wireshark is not installed.</summary>
    public string? TsharkPath { get; }

    public bool IsAvailable => TsharkPath is not null;

    /// <summary>
    /// Path to a TLS key log file (the file an app writes when <c>SSLKEYLOGFILE</c> is set).
    /// When set, every tshark operation decrypts TLS traffic. Null or empty disables decryption.
    /// </summary>
    public string? TlsKeyLogFile { get; set; }

    // ---- public operations ----------------------------------------------

    public async Task<string> GetVersionAsync(CancellationToken ct = default)
    {
        if (TsharkPath is null)
            return "tshark not found";
        string output = await RunAsync(new[] { "-v" }, ct, timeoutMs: 10_000, applyTlsKeyLog: false);
        return output.Split('\n').FirstOrDefault()?.Trim() ?? "unknown";
    }

    /// <summary>Runs a Wireshark display filter and returns matching packets as summaries.</summary>
    public async Task<IReadOnlyList<PacketSummary>> SearchAsync(
        string filePath, string? displayFilter, CancellationToken ct = default)
    {
        var args = new List<string> { "-r", filePath };
        if (!string.IsNullOrWhiteSpace(displayFilter))
        {
            args.Add("-Y");
            args.Add(displayFilter);
        }
        args.Add("-T");
        args.Add("fields");
        foreach (var field in SearchFields)
        {
            args.Add("-e");
            args.Add(field);
        }

        string output = await RunAsync(args, ct);
        var result = new List<PacketSummary>();
        foreach (var rawLine in output.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
                continue;

            string[] f = line.Split('\t');
            if (f.Length < SearchFields.Length)
                continue;

            result.Add(new PacketSummary
            {
                Number = ParseInt(f[0]),
                Timestamp = DateTimeOffset.UnixEpoch.AddSeconds(ParseDouble(f[1])),
                TimeOffsetSeconds = ParseDouble(f[2]),
                Source = f[3],
                Destination = f[4],
                Protocol = f[5],
                Length = ParseInt(f[6]),
                Info = string.Join('\t', f[7..]),
            });
        }
        return result;
    }

    /// <summary>Returns the full per-field protocol dissection tree for one packet (via PDML).</summary>
    public async Task<PacketDetail> GetDetailAsync(
        string filePath, int frameNumber, CancellationToken ct = default)
    {
        string xml = await RunAsync(
            new[] { "-r", filePath, "-Y", $"frame.number=={frameNumber}", "-T", "pdml" }, ct);

        var detail = new PacketDetail { Number = frameNumber };
        try
        {
            var doc = XDocument.Parse(xml);
            var packet = doc.Root?.Element("packet");
            if (packet is not null)
            {
                foreach (var proto in packet.Elements("proto"))
                    detail.Protocols.Add(ConvertPdmlNode(proto));
            }
        }
        catch (Exception ex)
        {
            detail.Protocols.Add(new PacketDetailNode
            {
                Label = "Could not parse dissection",
                Value = ex.Message,
            });
        }
        return detail;
    }

    /// <summary>Conversation statistics for a layer: tcp, udp, ip, ipv6 or eth.</summary>
    public async Task<IReadOnlyList<Conversation>> GetConversationsAsync(
        string filePath, string type, CancellationToken ct = default)
    {
        type = type.Trim().ToLowerInvariant();
        if (type is not ("tcp" or "udp" or "ip" or "ipv6" or "eth"))
            throw new ArgumentException("type must be one of: tcp, udp, ip, ipv6, eth", nameof(type));

        string output = await RunAsync(
            new[] { "-r", filePath, "-q", "-z", $"conv,{type}" }, ct);
        return ParseConversations(output, type);
    }

    /// <summary>The capture's protocol hierarchy (tshark -z io,phs).</summary>
    public async Task<IReadOnlyList<ProtocolHierarchyNode>> GetProtocolHierarchyAsync(
        string filePath, CancellationToken ct = default)
    {
        string output = await RunAsync(
            new[] { "-r", filePath, "-q", "-z", "io,phs" }, ct);
        return ParseProtocolHierarchy(output);
    }

    /// <summary>Reassembles and returns a single stream as text.</summary>
    /// <param name="protocol">tcp, udp, http or tls.</param>
    /// <param name="mode">ascii, hex or raw.</param>
    public async Task<string> FollowStreamAsync(
        string filePath, string protocol, int streamIndex, string mode = "ascii",
        CancellationToken ct = default)
    {
        protocol = protocol.Trim().ToLowerInvariant();
        mode = mode.Trim().ToLowerInvariant();
        if (protocol is not ("tcp" or "udp" or "http" or "tls"))
            throw new ArgumentException("protocol must be one of: tcp, udp, http, tls", nameof(protocol));
        if (mode is not ("ascii" or "hex" or "raw"))
            throw new ArgumentException("mode must be one of: ascii, hex, raw", nameof(mode));

        return await RunAsync(
            new[] { "-r", filePath, "-q", "-z", $"follow,{protocol},{mode},{streamIndex}" }, ct);
    }

    /// <summary>Carves transferred objects out of the capture into <paramref name="outputDirectory"/>.</summary>
    public async Task<IReadOnlyList<ExtractedObject>> ExtractObjectsAsync(
        string filePath, string protocol, string outputDirectory, CancellationToken ct = default)
    {
        protocol = protocol.Trim().ToLowerInvariant();
        Directory.CreateDirectory(outputDirectory);

        await RunAsync(
            new[] { "-r", filePath, "-q", "--export-objects", $"{protocol},{outputDirectory}" }, ct);

        var objects = new List<ExtractedObject>();
        foreach (var file in Directory.GetFiles(outputDirectory))
        {
            var fi = new FileInfo(file);
            objects.Add(new ExtractedObject
            {
                Name = fi.Name,
                SizeBytes = fi.Length,
                SavedPath = fi.FullName,
            });
        }
        return objects;
    }

    // ---- process plumbing -----------------------------------------------

    private async Task<string> RunAsync(
        IReadOnlyList<string> args, CancellationToken ct, int timeoutMs = 120_000,
        bool applyTlsKeyLog = true)
    {
        if (TsharkPath is null)
            throw new InvalidOperationException(
                "tshark (Wireshark) was not found. Install Wireshark to use search, dissection and statistics.");

        var psi = new ProcessStartInfo
        {
            FileName = TsharkPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        // Enable TLS decryption for every file-reading operation when a key log is set.
        if (applyTlsKeyLog && !string.IsNullOrWhiteSpace(TlsKeyLogFile))
        {
            psi.ArgumentList.Add("-o");
            psi.ArgumentList.Add($"tls.keylog_file:{TlsKeyLogFile}");
        }
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = psi };
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);

        process.Start();
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);

        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            if (ct.IsCancellationRequested)
                throw;
            throw new TimeoutException($"tshark did not finish within {timeoutMs / 1000}s.");
        }

        string stdout = await stdoutTask;
        string stderr = await stderrTask;

        if (process.ExitCode != 0 && stdout.Length == 0)
            throw new InvalidOperationException(
                $"tshark exited with code {process.ExitCode}: {stderr.Trim()}");

        return stdout;
    }

    private static string? Locate()
    {
        var candidates = new List<string>();

        string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir))
                continue;
            try
            {
                candidates.Add(Path.Combine(dir, "tshark.exe"));
                candidates.Add(Path.Combine(dir, "tshark"));
            }
            catch { /* malformed PATH entry */ }
        }

        candidates.Add(@"C:\Program Files\Wireshark\tshark.exe");
        candidates.Add(@"C:\Program Files (x86)\Wireshark\tshark.exe");
        candidates.Add("/usr/bin/tshark");
        candidates.Add("/usr/local/bin/tshark");
        candidates.Add("/opt/homebrew/bin/tshark");

        return candidates.FirstOrDefault(File.Exists);
    }

    // ---- output parsing -------------------------------------------------

    private static PacketDetailNode ConvertPdmlNode(XElement element)
    {
        var node = new PacketDetailNode
        {
            Label = BuildLabel(element),
            Value = element.Attribute("value")?.Value,
        };

        foreach (var child in element.Elements())
        {
            if (child.Name.LocalName is "proto" or "field")
                node.Children.Add(ConvertPdmlNode(child));
        }
        return node;
    }

    /// <summary>
    /// PDML fields under some protos (geninfo, …) put the bare label in <c>showname</c>
    /// and the value in <c>show</c>; for those, combine them like Wireshark renders.
    /// Most other fields already have "Label: value" in <c>showname</c>.
    /// </summary>
    private static string BuildLabel(XElement element)
    {
        string? showname = element.Attribute("showname")?.Value;
        string? show     = element.Attribute("show")?.Value;

        if (!string.IsNullOrEmpty(showname))
        {
            if (!showname.Contains(": ") && !string.IsNullOrEmpty(show))
                return $"{showname}: {show}";
            return showname;
        }

        return show
            ?? element.Attribute("name")?.Value
            ?? element.Name.LocalName;
    }

    private static IReadOnlyList<Conversation> ParseConversations(string output, string type)
    {
        var conversations = new List<Conversation>();
        foreach (var rawLine in output.Split('\n'))
        {
            var match = ConversationLineRegex().Match(rawLine);
            if (!match.Success)
                continue;

            var numbers = NumberTokenRegex()
                .Matches(match.Groups[3].Value)
                .Select(m => m.Value.Replace(",", ""))
                .ToArray();
            if (numbers.Length < 8)
                continue;

            conversations.Add(new Conversation
            {
                Protocol = type,
                EndpointA = match.Groups[1].Value,
                EndpointB = match.Groups[2].Value,
                FramesBToA = ParseLong(numbers[0]),
                BytesBToA = ParseLong(numbers[1]),
                FramesAToB = ParseLong(numbers[2]),
                BytesAToB = ParseLong(numbers[3]),
                TotalFrames = ParseLong(numbers[4]),
                TotalBytes = ParseLong(numbers[5]),
                RelativeStartSeconds = ParseDouble(numbers[6]),
                DurationSeconds = ParseDouble(numbers[7]),
            });
        }
        return conversations;
    }

    private static IReadOnlyList<ProtocolHierarchyNode> ParseProtocolHierarchy(string output)
    {
        var roots = new List<ProtocolHierarchyNode>();
        var stack = new Stack<ProtocolHierarchyNode>();

        foreach (var rawLine in output.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            var match = PhsLineRegex().Match(line);
            if (!match.Success)
                continue;

            int depth = match.Groups[1].Value.Length / 2;
            var node = new ProtocolHierarchyNode
            {
                Protocol = match.Groups[2].Value,
                Frames = ParseLong(match.Groups[3].Value),
                Bytes = ParseLong(match.Groups[4].Value),
                Depth = depth,
            };

            while (stack.Count > depth)
                stack.Pop();

            if (stack.Count == 0)
                roots.Add(node);
            else
                stack.Peek().Children.Add(node);

            stack.Push(node);
        }
        return roots;
    }

    private static int ParseInt(string s)
        => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private static long ParseLong(string s)
        => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private static double ParseDouble(string s)
        => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : 0;

    [GeneratedRegex(@"^(\S+)\s+<->\s+(\S+)\s+(.+)$")]
    private static partial Regex ConversationLineRegex();

    [GeneratedRegex(@"[-+]?[\d.,]+")]
    private static partial Regex NumberTokenRegex();

    [GeneratedRegex(@"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)")]
    private static partial Regex PhsLineRegex();
}
