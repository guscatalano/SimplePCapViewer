"""Generate a synthetic .pcap for Microsoft Store screenshots.

Everything in here is fake. Hosts use documentation/example ranges:
  - 192.0.2.0/24   (TEST-NET-1, RFC 5737)
  - 198.51.100.0/24 (TEST-NET-2)
  - example.com    (RFC 2606)
The local side uses 192.168.7.42, a private address.
"""

import os
import time
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

LOCAL_MAC = "f4:5c:89:11:22:33"
LOCAL_IP  = "192.168.7.42"
GW_MAC    = "00:50:56:c0:00:01"
GW_IP     = "192.168.7.1"

DNS_IP    = "192.168.7.1"
WEB_IP    = "198.51.100.27"      # example.com (fake)
API_IP    = "203.0.113.88"       # api.example.com (fake)
PING_IP   = "192.0.2.1"

t = time.time() - 1.5   # anchor so packets overlap the demo .evtx (also generated just now)
packets = []

def E(src=LOCAL_MAC, dst=GW_MAC):
    return Ether(src=src, dst=dst)

def add(p, dt=0.001):
    global t
    t += dt
    p.time = t
    packets.append(p)

# --- ARP who-has gateway (boring start, sets the scene) ---
add(E(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=LOCAL_MAC, psrc=LOCAL_IP, pdst=GW_IP), dt=0)
add(E(src=GW_MAC, dst=LOCAL_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=LOCAL_MAC, pdst=LOCAL_IP), dt=0.0008)

# --- DNS A query/response for example.com ---
add(E() / IP(src=LOCAL_IP, dst=DNS_IP) / UDP(sport=51324, dport=53)
        / DNS(id=0x1a2b, rd=1, qd=DNSQR(qname="example.com")), dt=0.04)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=DNS_IP, dst=LOCAL_IP) / UDP(sport=53, dport=51324)
        / DNS(id=0x1a2b, qr=1, aa=0, rd=1, ra=1,
              qd=DNSQR(qname="example.com"),
              an=DNSRR(rrname="example.com", ttl=300, rdata=WEB_IP)), dt=0.018)

# --- TCP handshake to example.com:80 ---
sport_http = 52310
seq_c, seq_s = 1000, 5000
add(E() / IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=sport_http, dport=80, flags="S",
                                              seq=seq_c, window=64240,
                                              options=[("MSS", 1460), ("SAckOK", b""),
                                                       ("Timestamp", (12345, 0)), ("NOP", None),
                                                       ("WScale", 8)]), dt=0.012)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=WEB_IP, dst=LOCAL_IP) / TCP(sport=80, dport=sport_http,
                                                                       flags="SA", seq=seq_s, ack=seq_c+1,
                                                                       window=65535,
                                                                       options=[("MSS", 1460), ("SAckOK", b""),
                                                                                ("Timestamp", (98765, 12345)),
                                                                                ("NOP", None), ("WScale", 7)]), dt=0.041)
add(E() / IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=sport_http, dport=80, flags="A",
                                              seq=seq_c+1, ack=seq_s+1, window=64240), dt=0.0003)

# --- HTTP GET / and 200 OK ---
http_req = (b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: SimplePCapViewer-demo/1.1.0\r\n"
            b"Accept: text/html,application/xhtml+xml\r\n"
            b"Accept-Language: en-US,en;q=0.9\r\n"
            b"Connection: keep-alive\r\n\r\n")
add(E() / IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=sport_http, dport=80, flags="PA",
                                              seq=seq_c+1, ack=seq_s+1, window=64240) / Raw(http_req), dt=0.0015)
seq_c += 1 + len(http_req)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=WEB_IP, dst=LOCAL_IP) / TCP(sport=80, dport=sport_http,
                                                                       flags="A", seq=seq_s+1, ack=seq_c,
                                                                       window=65535), dt=0.038)

http_resp_body = (b"<!doctype html><html><head><title>Example Domain</title></head>"
                  b"<body><h1>Example Domain</h1><p>This domain is for use in illustrative "
                  b"examples in documents. You may use this domain in literature without prior "
                  b"coordination or asking for permission.</p>"
                  b"<p><a href=\"https://www.iana.org/domains/example\">More information...</a></p>"
                  b"</body></html>")
http_resp = (b"HTTP/1.1 200 OK\r\n"
             b"Content-Type: text/html; charset=UTF-8\r\n"
             b"Server: ECS (dcb/7F84)\r\n"
             b"Cache-Control: max-age=604800\r\n"
             b"Date: Fri, 24 May 2024 16:00:01 GMT\r\n"
             b"Content-Length: " + str(len(http_resp_body)).encode() + b"\r\n\r\n") + http_resp_body
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=WEB_IP, dst=LOCAL_IP) / TCP(sport=80, dport=sport_http,
                                                                       flags="PA", seq=seq_s+1, ack=seq_c,
                                                                       window=65535) / Raw(http_resp), dt=0.002)
seq_s += 1 + len(http_resp)
add(E() / IP(src=LOCAL_IP, dst=WEB_IP) / TCP(sport=sport_http, dport=80, flags="A",
                                              seq=seq_c, ack=seq_s, window=64240), dt=0.0004)

# --- ICMP echo to a documentation IP ---
add(E() / IP(src=LOCAL_IP, dst=PING_IP) / ICMP(id=0x4321, seq=1) / Raw(b"abcdefghijklmnopqrstuvwxyz012345"), dt=0.21)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=PING_IP, dst=LOCAL_IP) / ICMP(type=0, id=0x4321, seq=1) / Raw(b"abcdefghijklmnopqrstuvwxyz012345"), dt=0.024)

# --- DNS A for api.example.com ---
add(E() / IP(src=LOCAL_IP, dst=DNS_IP) / UDP(sport=51325, dport=53)
        / DNS(id=0x77a3, rd=1, qd=DNSQR(qname="api.example.com")), dt=0.15)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=DNS_IP, dst=LOCAL_IP) / UDP(sport=53, dport=51325)
        / DNS(id=0x77a3, qr=1, rd=1, ra=1,
              qd=DNSQR(qname="api.example.com"),
              an=DNSRR(rrname="api.example.com", ttl=120, rdata=API_IP)), dt=0.02)

# --- TLS to api.example.com:443 (handshake bytes are real format so Wireshark dissects them) ---
sport_tls = 52311
sc, ss = 9000, 31000
add(E() / IP(src=LOCAL_IP, dst=API_IP) / TCP(sport=sport_tls, dport=443, flags="S", seq=sc, window=64240,
                                              options=[("MSS",1460),("SAckOK",b""),("Timestamp",(54321,0)),("NOP",None),("WScale",8)]), dt=0.02)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=API_IP, dst=LOCAL_IP) / TCP(sport=443, dport=sport_tls, flags="SA", seq=ss, ack=sc+1, window=65535,
                                                                       options=[("MSS",1460),("SAckOK",b""),("Timestamp",(11111,54321)),("NOP",None),("WScale",7)]), dt=0.045)
add(E() / IP(src=LOCAL_IP, dst=API_IP) / TCP(sport=sport_tls, dport=443, flags="A", seq=sc+1, ack=ss+1, window=64240), dt=0.0003)

# Minimal TLS 1.2 ClientHello — random + SNI for api.example.com.
sni_host = b"api.example.com"
sni_ext  = (b"\x00\x00"                                   # extension type = server_name
            + (5 + len(sni_host)).to_bytes(2,"big")       # ext length
            + (3 + len(sni_host)).to_bytes(2,"big")       # server name list length
            + b"\x00"                                     # name type = host_name
            + len(sni_host).to_bytes(2,"big") + sni_host)
versions_ext = b"\x00\x2b" + (1+4).to_bytes(2,"big") + b"\x04" + b"\x03\x04\x03\x03"  # supported_versions: TLS1.3, TLS1.2
extensions = sni_ext + versions_ext
client_hello_body = (b"\x03\x03"                            # client_version = TLS1.2
                     + b"\xaa\xbb\xcc\xdd" + b"\x11"*28     # random (32 bytes)
                     + b"\x00"                              # session_id length
                     + (2*4).to_bytes(2,"big")              # cipher_suites length
                     + b"\x13\x01\x13\x02\x13\x03\xc0\x2f"  # 4 ciphers
                     + b"\x01\x00"                          # compression methods
                     + len(extensions).to_bytes(2,"big") + extensions)
handshake = b"\x01" + len(client_hello_body).to_bytes(3,"big") + client_hello_body  # type 1 = ClientHello
tls_record = b"\x16\x03\x01" + len(handshake).to_bytes(2,"big") + handshake          # ContentType=Handshake
add(E() / IP(src=LOCAL_IP, dst=API_IP) / TCP(sport=sport_tls, dport=443, flags="PA",
                                              seq=sc+1, ack=ss+1, window=64240) / Raw(tls_record), dt=0.0011)
sc += 1 + len(tls_record)

# ServerHello + dummy ChangeCipherSpec + encrypted handshake (just bytes — Wireshark labels as Application Data)
server_hello_body = (b"\x03\x03" + b"\x55\x66\x77\x88" + b"\x22"*28 + b"\x00"
                     + b"\x13\x01"           # cipher TLS_AES_128_GCM_SHA256
                     + b"\x00"               # compression
                     + b"\x00\x06\x00\x2b\x00\x02\x03\x04")  # supported_versions ext = TLS 1.3
sh = b"\x02" + len(server_hello_body).to_bytes(3,"big") + server_hello_body
sh_record = b"\x16\x03\x03" + len(sh).to_bytes(2,"big") + sh
ccs_record = b"\x14\x03\x03\x00\x01\x01"
appdata    = b"\x17\x03\x03\x00\x20" + b"\xde\xad\xbe\xef" * 8
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=API_IP, dst=LOCAL_IP) / TCP(sport=443, dport=sport_tls, flags="PA",
                                                                       seq=ss+1, ack=sc, window=65535)
        / Raw(sh_record + ccs_record + appdata), dt=0.046)

# --- second DNS, for variety ---
add(E() / IP(src=LOCAL_IP, dst=DNS_IP) / UDP(sport=51326, dport=53)
        / DNS(id=0x9090, rd=1, qd=DNSQR(qname="cdn.example.com")), dt=0.32)
add(E(src=GW_MAC, dst=LOCAL_MAC) / IP(src=DNS_IP, dst=LOCAL_IP) / UDP(sport=53, dport=51326)
        / DNS(id=0x9090, qr=1, rd=1, ra=1,
              qd=DNSQR(qname="cdn.example.com"),
              an=DNSRR(rrname="cdn.example.com", ttl=60, rdata="198.51.100.200")), dt=0.019)

out = os.path.join(SCRIPT_DIR, "demo.pcap")
wrpcap(out, packets)
print(f"wrote {out} ({len(packets)} packets)")
