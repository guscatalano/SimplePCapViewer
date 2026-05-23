namespace PcapViewer.Core.Tests;

/// <summary>Builds tiny in-memory capture files (no Wireshark needed) for the reader tests.</summary>
internal static class TestCaptures
{
    /// <summary>An Ethernet + IPv4 + UDP frame (46 bytes): 192.168.1.10:12345 -> 192.168.1.20:53, payload "test".</summary>
    public static byte[] BuildUdpFrame()
    {
        var frame = new List<byte>();

        // Ethernet II
        frame.AddRange(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }); // destination MAC
        frame.AddRange(new byte[] { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB }); // source MAC
        frame.AddRange(new byte[] { 0x08, 0x00 });                         // EtherType = IPv4

        // IPv4 header (20 bytes)
        frame.AddRange(new byte[]
        {
            0x45, 0x00,             // version 4, IHL 5, DSCP/ECN 0
            0x00, 0x20,             // total length = 32
            0x00, 0x00,             // identification
            0x00, 0x00,             // flags / fragment offset
            0x40,                   // TTL = 64
            0x11,                   // protocol = 17 (UDP)
            0x00, 0x00,             // header checksum (ignored by the parser)
            192, 168, 1, 10,        // source address
            192, 168, 1, 20,        // destination address
        });

        // UDP header (8 bytes)
        frame.AddRange(new byte[]
        {
            0x30, 0x39,             // source port = 12345
            0x00, 0x35,             // destination port = 53
            0x00, 0x0C,             // length = 12
            0x00, 0x00,             // checksum
        });

        // Payload
        frame.AddRange(System.Text.Encoding.ASCII.GetBytes("test"));
        return frame.ToArray();
    }

    /// <summary>Wraps a frame in a classic little-endian libpcap file.</summary>
    public static byte[] BuildClassicPcap(byte[] frame)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write(0xA1B2C3D4u);          // magic (LE, microsecond)
        w.Write((ushort)2);            // version major
        w.Write((ushort)4);            // version minor
        w.Write(0);                    // thiszone
        w.Write(0u);                   // sigfigs
        w.Write(65535u);               // snaplen
        w.Write(1u);                   // network = Ethernet

        w.Write(1_700_000_000u);       // ts_sec
        w.Write(123_456u);             // ts_usec
        w.Write((uint)frame.Length);   // incl_len
        w.Write((uint)frame.Length);   // orig_len
        w.Write(frame);

        w.Flush();
        return ms.ToArray();
    }

    /// <summary>Wraps a frame in a pcapng file (Section Header + Interface Description + Enhanced Packet).</summary>
    public static byte[] BuildPcapNg(byte[] frame)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // Section Header Block (28 bytes)
        w.Write(0x0A0D0D0Au);                  // block type
        w.Write(28u);                          // block total length
        w.Write(0x1A2B3C4Du);                  // byte-order magic
        w.Write((ushort)1);                    // major version
        w.Write((ushort)0);                    // minor version
        w.Write(0xFFFFFFFFFFFFFFFFuL);         // section length (unspecified)
        w.Write(28u);                          // block total length (trailer)

        // Interface Description Block (20 bytes)
        w.Write(0x00000001u);                  // block type
        w.Write(20u);                          // block total length
        w.Write((ushort)1);                    // link type = Ethernet
        w.Write((ushort)0);                    // reserved
        w.Write(65535u);                       // snap length
        w.Write(20u);                          // block total length (trailer)

        // Enhanced Packet Block
        int padding = (4 - frame.Length % 4) % 4;
        uint total = (uint)(32 + frame.Length + padding);
        w.Write(0x00000006u);                  // block type
        w.Write(total);                        // block total length
        w.Write(0u);                           // interface id
        w.Write(0u);                           // timestamp high
        w.Write(0u);                           // timestamp low
        w.Write((uint)frame.Length);           // captured length
        w.Write((uint)frame.Length);           // original length
        w.Write(frame);
        for (int i = 0; i < padding; i++)
            w.Write((byte)0);
        w.Write(total);                        // block total length (trailer)

        w.Flush();
        return ms.ToArray();
    }

    /// <summary>Writes <paramref name="data"/> to a unique temp file and returns its path.</summary>
    public static string WriteTempFile(byte[] data, string extension)
    {
        string path = Path.Combine(
            Path.GetTempPath(), $"pcapviewer-test-{Guid.NewGuid():N}{extension}");
        File.WriteAllBytes(path, data);
        return path;
    }
}
