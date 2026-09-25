"""Unit tests for sniffer.parse_packet. Run with:  python -m unittest discover tests"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Ether, Raw  # noqa: E402

import sniffer  # noqa: E402


def stamp(pkt):
    pkt.time = time.time()
    return pkt


class ParsePacketTests(unittest.TestCase):
    def test_tcp_syn(self):
        rec = sniffer.parse_packet(stamp(
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=22, flags="S")))
        self.assertEqual(rec["protocol"], "TCP")
        self.assertEqual((rec["src"], rec["dst"]), ("10.0.0.1", "10.0.0.2"))
        self.assertEqual((rec["sport"], rec["dport"]), (1234, 22))
        self.assertEqual(rec["flags"], "S")
        self.assertEqual(rec["service"], "SSH")

    def test_udp_dns_query(self):
        rec = sniffer.parse_packet(stamp(
            Ether() / IP(dst="1.1.1.1") / UDP(sport=5353, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.org"))))
        self.assertEqual(rec["protocol"], "UDP")
        self.assertEqual(rec["service"], "DNS")
        self.assertIn("example.org", rec["info"])
        self.assertTrue(sniffer.matches_protocol(rec, "dns"))

    def test_http_request_detected_from_payload(self):
        rec = sniffer.parse_packet(stamp(
            Ether() / IP() / TCP(dport=8000) / Raw(b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n")))
        self.assertEqual(rec["service"], "HTTP")
        self.assertEqual(rec["info"], "GET /login HTTP/1.1")
        self.assertTrue(sniffer.matches_protocol(rec, "http"))

    def test_icmp_echo(self):
        rec = sniffer.parse_packet(stamp(Ether() / IP() / ICMP(type=8)))
        self.assertEqual(rec["protocol"], "ICMP")
        self.assertEqual(rec["info"], "echo-request")

    def test_arp_request(self):
        rec = sniffer.parse_packet(stamp(
            Ether() / ARP(op=1, psrc="192.168.0.5", pdst="192.168.0.1")))
        self.assertEqual(rec["protocol"], "ARP")
        self.assertIn("who-has 192.168.0.1", rec["info"])

    def test_ipv6_tcp(self):
        rec = sniffer.parse_packet(stamp(
            Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(dport=443)))
        self.assertEqual(rec["protocol"], "TCP")
        self.assertEqual(rec["dst"], "fe80::2")
        self.assertEqual(sniffer.endpoint(rec["dst"], rec["dport"]), "[fe80::2]:443")

    def test_control_characters_are_neutralised(self):
        evil = b"GET /\x1b[2Jpwned HTTP/1.1\r\n\r\n"
        rec = sniffer.parse_packet(stamp(Ether() / IP() / TCP(dport=80) / Raw(evil)))
        self.assertNotIn("\x1b", rec["info"])

    def test_csv_formula_injection_is_escaped(self):
        self.assertEqual(sniffer.PacketLogger._csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(sniffer.PacketLogger._csv_safe("normal"), "normal")

    def test_protocol_filter(self):
        rec = sniffer.parse_packet(stamp(Ether() / IP() / UDP(dport=9999)))
        self.assertTrue(sniffer.matches_protocol(rec, "udp"))
        self.assertFalse(sniffer.matches_protocol(rec, "tcp"))
        self.assertTrue(sniffer.matches_protocol(rec, "all"))


if __name__ == "__main__":
    unittest.main()
