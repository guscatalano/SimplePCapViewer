using PacketDotNet;
using PcapViewer.Core.Models;

namespace PcapViewer.Core.Dissection;

/// <summary>
/// Builds a <see cref="PacketSummary"/> from a raw frame using PacketDotNet.
/// This is the fast, in-process path that fills the packet list immediately on load;
/// deep per-field dissection is delegated to tshark.
/// </summary>
public static class PacketSummaryBuilder
{
    private static readonly Dictionary<int, string> WellKnownPorts = new()
    {
        [20] = "FTP-DATA", [21] = "FTP", [22] = "SSH", [23] = "TELNET", [25] = "SMTP",
        [53] = "DNS", [67] = "DHCP", [68] = "DHCP", [69] = "TFTP", [80] = "HTTP",
        [110] = "POP", [123] = "NTP", [143] = "IMAP", [161] = "SNMP", [389] = "LDAP",
        [443] = "TLS", [445] = "SMB", [465] = "SMTPS", [514] = "SYSLOG", [587] = "SMTP",
        [636] = "LDAPS", [993] = "IMAPS", [995] = "POPS", [1900] = "SSDP", [3389] = "RDP",
        [5353] = "MDNS", [5060] = "SIP", [8080] = "HTTP", [8443] = "TLS",
    };

    public static PacketSummary Build(RawFrame frame, DateTimeOffset captureStart)
    {
        string source = "";
        string destination = "";
        string protocol = "Unknown";
        string info = "";

        try
        {
            var packet = Packet.ParsePacket((LinkLayers)frame.LinkType, frame.Data);

            var ip = packet.Extract<IPPacket>();
            var tcp = packet.Extract<TcpPacket>();
            var udp = packet.Extract<UdpPacket>();
            var arp = packet.Extract<ArpPacket>();
            var icmpV4 = packet.Extract<IcmpV4Packet>();
            var icmpV6 = packet.Extract<IcmpV6Packet>();
            var eth = packet.Extract<EthernetPacket>();

            if (ip is not null)
            {
                source = ip.SourceAddress.ToString();
                destination = ip.DestinationAddress.ToString();
            }
            else if (arp is not null)
            {
                source = arp.SenderProtocolAddress?.ToString() ?? "";
                destination = arp.TargetProtocolAddress?.ToString() ?? "";
            }
            else if (eth is not null)
            {
                source = eth.SourceHardwareAddress?.ToString() ?? "";
                destination = eth.DestinationHardwareAddress?.ToString() ?? "";
            }

            if (tcp is not null)
            {
                protocol = PortProtocol(tcp.SourcePort, tcp.DestinationPort) ?? "TCP";
                int payload = tcp.PayloadData?.Length ?? 0;
                info = $"{tcp.SourcePort} → {tcp.DestinationPort} [{TcpFlags(tcp)}] " +
                       $"Seq={tcp.SequenceNumber} Win={tcp.WindowSize} Len={payload}";
            }
            else if (udp is not null)
            {
                protocol = PortProtocol(udp.SourcePort, udp.DestinationPort) ?? "UDP";
                info = $"{udp.SourcePort} → {udp.DestinationPort} Len={udp.Length}";
            }
            else if (icmpV4 is not null)
            {
                protocol = "ICMP";
                info = icmpV4.TypeCode.ToString();
            }
            else if (icmpV6 is not null)
            {
                protocol = "ICMPv6";
                info = icmpV6.Type.ToString();
            }
            else if (arp is not null)
            {
                protocol = "ARP";
                info = arp.Operation == ArpOperation.Request
                    ? $"Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}"
                    : $"{arp.SenderProtocolAddress} is at {arp.SenderHardwareAddress}";
            }
            else if (ip is not null)
            {
                protocol = ip.Protocol.ToString();
            }
            else if (eth is not null)
            {
                protocol = eth.Type.ToString();
            }
        }
        catch
        {
            // A malformed or unsupported frame must never abort loading — degrade gracefully.
            protocol = "Unknown";
        }

        return new PacketSummary
        {
            Number = frame.Number,
            Timestamp = frame.Timestamp,
            TimeOffsetSeconds = (frame.Timestamp - captureStart).TotalSeconds,
            Source = source,
            Destination = destination,
            Protocol = protocol,
            Length = frame.OriginalLength,
            Info = info,
        };
    }

    private static string TcpFlags(TcpPacket tcp)
    {
        var flags = new List<string>(6);
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Urgent) flags.Add("URG");
        return flags.Count == 0 ? "—" : string.Join(", ", flags);
    }

    private static string? PortProtocol(int portA, int portB)
    {
        if (WellKnownPorts.TryGetValue(portA, out var name)) return name;
        if (WellKnownPorts.TryGetValue(portB, out name)) return name;
        return null;
    }
}
