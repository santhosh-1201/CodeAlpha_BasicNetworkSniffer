#!/usr/bin/env python3
"""
Generate samples/sample_traffic.pcap: a small, fully synthetic capture with a
mix of ARP, DNS, TCP (HTTP / HTTPS / FTP), ICMP and IPv6 packets.

Useful for testing and for demoing the sniffer without live network traffic:

    python tools/make_sample_pcap.py
    python sniffer.py -r samples/sample_traffic.pcap
"""

import os
import time

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, Ether,
                       Raw, wrpcap)

CLIENT_MAC, GW_MAC = "aa:bb:cc:00:00:20", "aa:bb:cc:00:00:01"
CLIENT, GATEWAY, WEB, FTP = "192.168.1.20", "192.168.1.1", "93.184.216.34", "203.0.113.7"

out = Ether(src=CLIENT_MAC, dst=GW_MAC)   # client -> gateway
back = Ether(src=GW_MAC, dst=CLIENT_MAC)  # gateway -> client


def build():
    http_get = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                b"User-Agent: demo\r\n\r\n")
    http_ok = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>"

    return [
        # ARP
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT, pdst=GATEWAY),
        back / ARP(op=2, hwsrc=GW_MAC, psrc=GATEWAY, hwdst=CLIENT_MAC, pdst=CLIENT),
        # DNS lookup
        out / IP(src=CLIENT, dst=GATEWAY) / UDP(sport=53211, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        back / IP(src=GATEWAY, dst=CLIENT) / UDP(sport=53, dport=53211)
        / DNS(qr=1, aa=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata=WEB)),
        # TCP handshake + HTTP request/response
        out / IP(src=CLIENT, dst=WEB) / TCP(sport=40100, dport=80, flags="S", seq=100),
        back / IP(src=WEB, dst=CLIENT) / TCP(sport=80, dport=40100, flags="SA", seq=500, ack=101),
        out / IP(src=CLIENT, dst=WEB) / TCP(sport=40100, dport=80, flags="A", seq=101, ack=501),
        out / IP(src=CLIENT, dst=WEB) / TCP(sport=40100, dport=80, flags="PA", seq=101, ack=501) / Raw(http_get),
        back / IP(src=WEB, dst=CLIENT) / TCP(sport=80, dport=40100, flags="PA", seq=501, ack=101 + len(http_get)) / Raw(http_ok),
        # HTTPS (encrypted payload: looks like random bytes)
        out / IP(src=CLIENT, dst=WEB) / TCP(sport=40200, dport=443, flags="S", seq=900),
        out / IP(src=CLIENT, dst=WEB) / TCP(sport=40200, dport=443, flags="PA", seq=901, ack=1)
        / Raw(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + bytes(range(40))),
        # Plain-text FTP login - shows why unencrypted protocols are risky
        out / IP(src=CLIENT, dst=FTP) / TCP(sport=40300, dport=21, flags="PA", seq=1, ack=1) / Raw(b"USER anonymous\r\n"),
        out / IP(src=CLIENT, dst=FTP) / TCP(sport=40300, dport=21, flags="PA", seq=17, ack=1) / Raw(b"PASS guest@example.com\r\n"),
        # ICMP ping
        out / IP(src=CLIENT, dst="8.8.8.8") / ICMP(type=8, id=1, seq=1) / Raw(b"abcdefgh"),
        back / IP(src="8.8.8.8", dst=CLIENT) / ICMP(type=0, id=1, seq=1) / Raw(b"abcdefgh"),
        # IPv6
        out / IPv6(src="fe80::1", dst="2001:db8::1") / TCP(sport=51000, dport=443, flags="S"),
        # UDP (NTP)
        out / IP(src=CLIENT, dst="129.6.15.28") / UDP(sport=51234, dport=123) / Raw(b"\x1b" + b"\x00" * 47),
        # TCP reset
        back / IP(src=FTP, dst=CLIENT) / TCP(sport=21, dport=40300, flags="RA", seq=1, ack=40),
    ]


if __name__ == "__main__":
    packets = build()
    start = time.time() - 60
    for i, pkt in enumerate(packets):
        pkt.time = start + i * 0.137
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "samples", "sample_traffic.pcap")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wrpcap(path, packets)
    print(f"wrote {len(packets)} packets to {path}")
