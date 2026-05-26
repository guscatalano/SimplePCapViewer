# Generates demo.evtx by writing a handful of synthetic events to the Application
# log under a custom source, then exporting only those events. Safe to re-run.
#
# Everything written here is fake -- hostnames use the documentation domain
# (example.com / RFC 2606) so it is obvious to a reviewer.

$ErrorActionPreference = 'Stop'
$source = 'SPCVDemo'
$out    = Join-Path $PSScriptRoot 'demo.evtx'

# Make sure the source exists. eventcreate registers it on first write.
$null = eventcreate /T INFORMATION /ID 1 /L APPLICATION /SO $source /D 'init' 2>$null

# eventcreate caps EventID at 1000, so use small synthetic IDs (not real provider IDs).
$events = @(
    @{ Type='INFORMATION'; ID=53;  Text='DNS query for example.com resolved to 198.51.100.27 (TTL 300s).' },
    @{ Type='INFORMATION'; ID=300; Text='TCP connection established: 192.168.7.42:52310 -> 198.51.100.27:80 (HTTP).' },
    @{ Type='INFORMATION'; ID=401; Text='Schannel: TLS 1.3 handshake completed with api.example.com (TLS_AES_128_GCM_SHA256).' },
    @{ Type='WARNING';     ID=501; Text='WLAN AutoConfig: roamed from BSSID 00:11:22:aa:bb:01 to 00:11:22:aa:bb:07 on SSID "office-5g" (RSSI -58 dBm).' },
    @{ Type='INFORMATION'; ID=601; Text='Filtering Platform Connection: outbound IPv4 allow, PID 9412 (msedge.exe), 192.168.7.42:52311 -> 203.0.113.88:443.' },
    @{ Type='WARNING';     ID=402; Text='Schannel: a fatal alert was received from the remote endpoint. The TLS protocol defined fatal alert code is 40.' },
    @{ Type='INFORMATION'; ID=53;  Text='DNS query for api.example.com resolved to 203.0.113.88 (TTL 120s).' },
    @{ Type='ERROR';       ID=701; Text='DNS-Client: Name resolution for stale.example.invalid timed out after none of the configured DNS servers responded.' },
    @{ Type='INFORMATION'; ID=301; Text='TCP connection closed by peer: 192.168.7.42:52310 -> 198.51.100.27:80 (HTTP) after 1.4s.' },
    @{ Type='INFORMATION'; ID=53;  Text='DNS query for cdn.example.com resolved to 198.51.100.200 (TTL 60s).' }
)

foreach ($e in $events) {
    & eventcreate /T $e.Type /ID $e.ID /L APPLICATION /SO $source /D $e.Text | Out-Null
    Start-Sleep -Milliseconds 80   # space them out so the timestamps order nicely
}

if (Test-Path $out) { Remove-Item $out -Force }
# Filter to events written in the last 10 seconds so prior runs don't leak in.
# The XPath needs a literal '<=' — keep it in a single-quoted string so PS doesn't redirect.
$q = '*[System[Provider[@Name=''' + $source + '''] and TimeCreated[timediff(@SystemTime) <= 10000]]]'
wevtutil epl Application $out /q:$q

$count = (wevtutil qe $out /lf:true /c:9999 /f:text | Select-String '^Event\[').Count
Write-Host "wrote $out (events: $count)"
