using System.Text;

namespace PcapViewer.Core.Pcap;

/// <summary>Formats raw frame bytes as a classic offset / hex / ASCII dump.</summary>
public static class HexDump
{
    public static string Format(byte[] data)
    {
        if (data.Length == 0)
            return "(no captured bytes)";

        var sb = new StringBuilder(data.Length / 16 * 76 + 16);
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append(i.ToString("x4")).Append("  ");
            int n = Math.Min(16, data.Length - i);

            for (int j = 0; j < 16; j++)
            {
                if (j < n)
                    sb.Append(data[i + j].ToString("x2")).Append(' ');
                else
                    sb.Append("   ");
                if (j == 7)
                    sb.Append(' ');
            }

            sb.Append(' ');
            for (int j = 0; j < n; j++)
            {
                byte b = data[i + j];
                sb.Append(b is >= 0x20 and < 0x7f ? (char)b : '.');
            }

            sb.Append('\n');
        }
        return sb.ToString();
    }
}
