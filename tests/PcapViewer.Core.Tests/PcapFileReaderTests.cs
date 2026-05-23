using PcapViewer.Core;
using PcapViewer.Core.Pcap;

namespace PcapViewer.Core.Tests;

public class PcapFileReaderTests
{
    [Fact]
    public void ReadsClassicPcap()
    {
        byte[] frame = TestCaptures.BuildUdpFrame();
        string path = TestCaptures.WriteTempFile(TestCaptures.BuildClassicPcap(frame), ".pcap");
        try
        {
            var capture = PcapFileReader.Read(path);

            Assert.Equal("pcap", capture.Format);
            Assert.Equal(1, capture.PrimaryLinkType);
            Assert.Single(capture.Frames);

            var f = capture.Frames[0];
            Assert.Equal(1, f.Number);
            Assert.Equal(frame.Length, f.OriginalLength);
            Assert.Equal(frame.Length, f.CapturedLength);
            Assert.Equal(frame, f.Data);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ReadsPcapNg()
    {
        byte[] frame = TestCaptures.BuildUdpFrame();
        string path = TestCaptures.WriteTempFile(TestCaptures.BuildPcapNg(frame), ".pcapng");
        try
        {
            var capture = PcapFileReader.Read(path);

            Assert.Equal("pcapng", capture.Format);
            Assert.Equal(1, capture.PrimaryLinkType);
            Assert.Single(capture.Frames);
            Assert.Equal(frame, capture.Frames[0].Data);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RejectsUnknownFormat()
    {
        // 24 bytes of non-capture data (enough to pass the size check, wrong magic).
        byte[] junk = Enumerable.Range(0, 24).Select(i => (byte)i).ToArray();
        string path = TestCaptures.WriteTempFile(junk, ".bin");
        try
        {
            Assert.Throws<InvalidDataException>(() => PcapFileReader.Read(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LoadsThroughPcapDocument()
    {
        byte[] frame = TestCaptures.BuildUdpFrame();
        string path = TestCaptures.WriteTempFile(TestCaptures.BuildClassicPcap(frame), ".pcap");
        try
        {
            var document = PcapDocument.Load(path);

            Assert.Equal(1, document.Info.PacketCount);
            Assert.Equal("pcap", document.Info.FileFormat);
            Assert.Equal("Ethernet", document.Info.LinkType);
            Assert.Single(document.Packets);
            Assert.NotEqual("", document.GetHexDump(1));

            // Native quick search over the summary columns.
            Assert.Single(document.QuickSearch("192.168.1.10"));
            Assert.Empty(document.QuickSearch("203.0.113.99"));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
