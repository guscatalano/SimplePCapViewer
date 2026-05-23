using PcapViewer.Core.Dissection;
using PcapViewer.Core.Models;
using PcapViewer.Core.Pcap;

namespace PcapViewer.Core.Tests;

public class PacketSummaryBuilderTests
{
    [Fact]
    public void DissectsUdpFrame()
    {
        byte[] frame = TestCaptures.BuildUdpFrame();
        var raw = new RawFrame
        {
            Number = 1,
            Timestamp = DateTimeOffset.UnixEpoch,
            CapturedLength = frame.Length,
            OriginalLength = frame.Length,
            Data = frame,
            LinkType = 1,
        };

        var summary = PacketSummaryBuilder.Build(raw, DateTimeOffset.UnixEpoch);

        Assert.Equal("192.168.1.10", summary.Source);
        Assert.Equal("192.168.1.20", summary.Destination);
        Assert.Equal("DNS", summary.Protocol); // destination port 53 is well-known
        Assert.Contains("12345", summary.Info);
        Assert.Contains("53", summary.Info);
        Assert.Equal(frame.Length, summary.Length);
    }

    [Fact]
    public void DegradesGracefullyOnGarbage()
    {
        var raw = new RawFrame
        {
            Number = 1,
            Data = new byte[] { 0x00, 0x01, 0x02, 0x03 },
            OriginalLength = 4,
            LinkType = 1,
        };

        // A malformed frame must never throw — it should yield a minimal summary.
        var summary = PacketSummaryBuilder.Build(raw, DateTimeOffset.UnixEpoch);

        Assert.NotNull(summary);
        Assert.Equal(1, summary.Number);
    }
}

public class HexDumpTests
{
    [Fact]
    public void FormatsOffsetHexAndAscii()
    {
        string dump = HexDump.Format(new byte[] { 0x48, 0x69 }); // "Hi"

        Assert.StartsWith("0000", dump);
        Assert.Contains("48 69", dump);
        Assert.Contains("Hi", dump);
    }

    [Fact]
    public void HandlesEmptyInput()
    {
        Assert.Equal("(no captured bytes)", HexDump.Format(Array.Empty<byte>()));
    }

    [Fact]
    public void NonPrintableBytesBecomeDots()
    {
        string dump = HexDump.Format(new byte[] { 0x00, 0xFF });

        Assert.Contains("00 ff", dump);
        Assert.Contains("..", dump);
    }
}
