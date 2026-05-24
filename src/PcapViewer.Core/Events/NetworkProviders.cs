namespace PcapViewer.Core.Events;

/// <summary>
/// Marks events as "network-relevant" by matching the publisher / ETW provider name and the
/// EVTX channel against a curated list. Used to filter attached events so they stay focused
/// on the pcap-companion use case rather than dragging in every event in a System log.
/// </summary>
internal static class NetworkProviders
{
    private const StringComparison Ci = StringComparison.OrdinalIgnoreCase;

    private static readonly HashSet<string> Providers = new(StringComparer.OrdinalIgnoreCase)
    {
        // ETW providers (Microsoft-Windows-... names also serve as EVTX publisher names)
        "Microsoft-Windows-TCPIP",
        "Microsoft-Windows-Winsock-AFD",
        "Microsoft-Windows-Winsock-NameResolution",
        "Microsoft-Windows-DNS-Client",
        "Microsoft-Windows-DHCP-Client",
        "Microsoft-Windows-Dhcpv6-Client",
        "Microsoft-Windows-Schannel-Events",
        "Microsoft-Windows-WinINet",
        "Microsoft-Windows-WinHTTP",
        "Microsoft-Windows-WebIO",
        "Microsoft-Windows-HttpService",
        "Microsoft-Windows-Http.sys",
        "Microsoft-Windows-WFP",
        "Microsoft-Windows-Windows Firewall With Advanced Security",
        "Microsoft-Windows-SMBClient",
        "Microsoft-Windows-SMBServer",
        "Microsoft-Windows-NetworkProfile",
        "Microsoft-Windows-NCSI",
        "Microsoft-Windows-WLAN-AutoConfig",
        "Microsoft-Windows-WiredAutoConfig",
        "Microsoft-Windows-WCM",
        "Microsoft-Windows-Iphlpsvc",
        "Microsoft-Windows-RPC",
        "Microsoft-Windows-RPCSS",
        "Microsoft-Windows-Kerberos-Key-Distribution-Center",
        "Microsoft-Windows-Security-Kerberos",
        "Microsoft-Windows-NTLM",
        "Microsoft-Windows-Networking-Correlation",
        "System.Net.Http",
        "System.Net.Sockets",
        "System.Net.NameResolution",
        "System.Net.Security",

        // Legacy / System-log "source" names
        "Schannel",
        "Tcpip",
        "Tcpip6",
        "Dhcp-Client",
        "Dhcpv6-Client",
        "DHCP",
        "DnsApi",
        "NetBT",
        "BFE",
        "RemoteAccess",
    };

    private static readonly string[] ChannelSubstrings =
    {
        "DNS-Client", "DHCP", "DHCPv6", "WLAN", "Wired-AutoConfig", "NetworkProfile",
        "NCSI", "Iphlpsvc", "SMBClient", "SMBServer", "WFP", "Firewall",
        "TCPIP", "Schannel", "Http", "WCM",
    };

    public static bool IsNetwork(string provider, string channel)
    {
        if (!string.IsNullOrEmpty(provider))
        {
            if (Providers.Contains(provider))
                return true;
            // Many providers come as "Microsoft-Windows-DNS-Client/Operational"-style channels but
            // also have suffixed provider names; check substrings too.
            foreach (var p in Providers)
                if (provider.Contains(p, Ci))
                    return true;
        }

        if (!string.IsNullOrEmpty(channel))
        {
            foreach (var s in ChannelSubstrings)
                if (channel.Contains(s, Ci))
                    return true;
        }

        return false;
    }
}
