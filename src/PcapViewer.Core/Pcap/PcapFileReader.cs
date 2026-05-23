using System.Buffers.Binary;
using PcapViewer.Core.Models;

namespace PcapViewer.Core.Pcap;

/// <summary>
/// Pure-managed reader for classic libpcap (.pcap) and pcapng (.pcapng) capture files.
/// No native dependency (Npcap/libpcap) is required.
/// </summary>
public static class PcapFileReader
{
    private static readonly DateTimeOffset Epoch = DateTimeOffset.UnixEpoch;

    // Classic pcap magic numbers (read little-endian).
    private const uint MagicUsecLe = 0xA1B2C3D4; // little-endian, microsecond resolution
    private const uint MagicUsecBe = 0xD4C3B2A1; // big-endian, microsecond resolution
    private const uint MagicNanoLe = 0xA1B23C4D; // little-endian, nanosecond resolution
    private const uint MagicNanoBe = 0x4D3CB2A1; // big-endian, nanosecond resolution

    private const uint BlockSectionHeader = 0x0A0D0D0A; // pcapng Section Header Block type (palindromic)
    private const uint BlockInterfaceDesc = 0x00000001;
    private const uint BlockPacketLegacy  = 0x00000002; // obsolete Packet Block
    private const uint BlockSimplePacket  = 0x00000003;
    private const uint BlockEnhancedPkt   = 0x00000006;
    private const uint ByteOrderMagic     = 0x1A2B3C4D;

    /// <summary>Reads every frame from the capture file at <paramref name="path"/>.</summary>
    public static PcapCapture Read(string path)
    {
        byte[] data = File.ReadAllBytes(path);
        if (data.Length < 24)
            throw new InvalidDataException("File is too small to be a capture file.");

        uint magicLe = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (magicLe == BlockSectionHeader)
            return ReadPcapNg(data);
        if (magicLe is MagicUsecLe or MagicUsecBe or MagicNanoLe or MagicNanoBe)
            return ReadClassic(data, magicLe);

        throw new InvalidDataException(
            "Unrecognized capture format. Expected a libpcap (.pcap) or pcapng (.pcapng) file.");
    }

    // ---- classic libpcap -------------------------------------------------

    private static PcapCapture ReadClassic(byte[] d, uint magic)
    {
        bool le = magic is MagicUsecLe or MagicNanoLe;
        bool nano = magic is MagicNanoLe or MagicNanoBe;
        int linkType = (int)U32(d, 20, le);

        var frames = new List<RawFrame>();
        int pos = 24;
        int number = 1;

        while (pos + 16 <= d.Length)
        {
            uint tsSec = U32(d, pos, le);
            uint tsFrac = U32(d, pos + 4, le);
            uint inclLen = U32(d, pos + 8, le);
            uint origLen = U32(d, pos + 12, le);
            pos += 16;

            int available = d.Length - pos;
            if (available <= 0)
                break;
            if (inclLen > (uint)available)
                inclLen = (uint)available; // truncated final record

            byte[] payload = new byte[inclLen];
            Array.Copy(d, pos, payload, 0, (int)inclLen);
            pos += (int)inclLen;

            double frac = nano ? tsFrac / 1_000_000_000.0 : tsFrac / 1_000_000.0;
            frames.Add(new RawFrame
            {
                Number = number++,
                Timestamp = Epoch.AddSeconds(tsSec).AddSeconds(frac),
                CapturedLength = (int)inclLen,
                OriginalLength = origLen == 0 ? (int)inclLen : (int)origLen,
                Data = payload,
                LinkType = linkType,
            });
        }

        return new PcapCapture { Frames = frames, Format = "pcap", PrimaryLinkType = linkType };
    }

    // ---- pcapng ----------------------------------------------------------

    private readonly record struct NgInterface(int LinkType, double TsDivisor)
    {
        public static NgInterface Default => new(1, 1_000_000.0);
    }

    private static PcapCapture ReadPcapNg(byte[] d)
    {
        var frames = new List<RawFrame>();
        var interfaces = new List<NgInterface>();
        bool le = true;
        int primaryLink = -1;
        int pos = 0;
        int number = 1;

        while (pos + 12 <= d.Length)
        {
            uint type = U32(d, pos, le);

            if (type == BlockSectionHeader)
            {
                // The byte-order magic in the SHB body fixes the endianness for this section.
                uint bom = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(pos + 8, 4));
                le = bom == ByteOrderMagic;
                interfaces.Clear();
            }

            uint total = U32(d, pos + 4, le);
            if (total < 12 || total % 4 != 0 || pos + (long)total > d.Length)
                break; // corrupt or truncated — stop gracefully

            int body = pos + 8;
            int blockEnd = pos + (int)total - 4; // exclusive end of body (before trailing length)

            switch (type)
            {
                case BlockInterfaceDesc:
                {
                    int linkType = U16(d, body, le);
                    double divisor = ParseTsResol(d, body + 8, blockEnd, le);
                    interfaces.Add(new NgInterface(linkType, divisor));
                    if (primaryLink < 0)
                        primaryLink = linkType;
                    break;
                }
                case BlockEnhancedPkt:
                {
                    int ifId = (int)U32(d, body, le);
                    uint tsHigh = U32(d, body + 4, le);
                    uint tsLow = U32(d, body + 8, le);
                    uint capLen = U32(d, body + 12, le);
                    uint origLen = U32(d, body + 16, le);
                    var iface = ifId >= 0 && ifId < interfaces.Count ? interfaces[ifId] : NgInterface.Default;
                    var frame = MakeFrame(d, body + 20, capLen, origLen, tsHigh, tsLow, iface, number);
                    if (frame is not null)
                    {
                        frames.Add(frame);
                        number++;
                    }
                    break;
                }
                case BlockSimplePacket:
                {
                    uint origLen = U32(d, body, le);
                    int avail = blockEnd - (body + 4);
                    uint capLen = (uint)Math.Max(0, Math.Min(origLen, (uint)Math.Max(0, avail)));
                    var iface = interfaces.Count > 0 ? interfaces[0] : NgInterface.Default;
                    var frame = MakeFrame(d, body + 4, capLen, origLen, 0, 0, iface, number);
                    if (frame is not null)
                    {
                        frames.Add(frame);
                        number++;
                    }
                    break;
                }
                case BlockPacketLegacy:
                {
                    int ifId = U16(d, body, le);
                    uint tsHigh = U32(d, body + 4, le);
                    uint tsLow = U32(d, body + 8, le);
                    uint capLen = U32(d, body + 12, le);
                    uint origLen = U32(d, body + 16, le);
                    var iface = ifId >= 0 && ifId < interfaces.Count ? interfaces[ifId] : NgInterface.Default;
                    var frame = MakeFrame(d, body + 20, capLen, origLen, tsHigh, tsLow, iface, number);
                    if (frame is not null)
                    {
                        frames.Add(frame);
                        number++;
                    }
                    break;
                }
            }

            pos += (int)total;
        }

        return new PcapCapture
        {
            Frames = frames,
            Format = "pcapng",
            PrimaryLinkType = primaryLink < 0 ? 1 : primaryLink,
        };
    }

    private static RawFrame? MakeFrame(
        byte[] d, int dataOffset, uint capLen, uint origLen,
        uint tsHigh, uint tsLow, NgInterface iface, int number)
    {
        if (dataOffset < 0 || dataOffset > d.Length)
            return null;
        if (capLen > (uint)(d.Length - dataOffset))
            capLen = (uint)(d.Length - dataOffset);

        byte[] payload = new byte[capLen];
        Array.Copy(d, dataOffset, payload, 0, (int)capLen);

        ulong ts = ((ulong)tsHigh << 32) | tsLow;
        var timestamp = ts == 0 ? Epoch : Epoch.AddSeconds(ts / iface.TsDivisor);

        return new RawFrame
        {
            Number = number,
            Timestamp = timestamp,
            CapturedLength = (int)capLen,
            OriginalLength = origLen == 0 ? (int)capLen : (int)origLen,
            Data = payload,
            LinkType = iface.LinkType,
        };
    }

    /// <summary>
    /// Scans an Interface Description Block's options for if_tsresol (code 9) and returns
    /// the timestamp divisor (ticks per second). Defaults to 1e6 (microseconds).
    /// </summary>
    private static double ParseTsResol(byte[] d, int start, int end, bool le)
    {
        int p = start;
        while (p + 4 <= end)
        {
            ushort code = U16(d, p, le);
            ushort len = U16(d, p + 2, le);
            p += 4;
            if (code == 0) // opt_endofopt
                break;
            if (code == 9 && len >= 1 && p < d.Length) // if_tsresol
            {
                byte b = d[p];
                return (b & 0x80) == 0 ? Math.Pow(10, b) : Math.Pow(2, b & 0x7F);
            }
            p += (len + 3) & ~3; // options are padded to 32-bit boundaries
        }
        return 1_000_000.0;
    }

    // ---- endian-aware primitives ----------------------------------------

    private static uint U32(byte[] b, int o, bool le) => le
        ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4))
        : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o, 4));

    private static ushort U16(byte[] b, int o, bool le) => le
        ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o, 2))
        : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o, 2));
}
