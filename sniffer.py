#!/usr/bin/env python3
"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship - Task 1
Author: Santhosh S

Captures packets from a network interface (or replays a .pcap file), decodes
the Ethernet / IP / TCP / UDP / ICMP / ARP / DNS layers and prints source and
destination addresses, protocol, ports, TCP flags and a payload preview.

Only capture traffic on networks you own or are explicitly authorised to
monitor.
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP, conf, sniff
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapWriter
except ImportError:
    sys.exit("scapy is not installed. Run: pip install -r requirements.txt")

conf.verb = 0  # keep scapy itself quiet

# --------------------------------------------------------------------------
# Lookup tables
# --------------------------------------------------------------------------
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}

ICMP_TYPES = {
    0: "echo-reply", 3: "destination-unreachable", 8: "echo-request",
    11: "time-exceeded",
}

HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
               b"PATCH ", b"HTTP/1.")

COLORS = {
    "TCP": "\033[36m", "UDP": "\033[33m", "ICMP": "\033[35m",
    "ICMPv6": "\033[35m", "ARP": "\033[32m",
}
RESET = "\033[0m"

# protocol names accepted by --protocol
PROTOCOL_CHOICES = ["all", "tcp", "udp", "icmp", "arp", "dns", "http"]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def safe_text(text):
    """Replace non-printable characters so captured data can never inject
    terminal escape sequences into our output."""
    return "".join(ch if ch.isprintable() else "." for ch in text)


def ascii_preview(data, limit):
    snippet = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
    return text + ("..." if len(data) > limit else "")


def hexdump(data, limit):
    data = data[:limit]
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"      {offset:04x}  {hex_part:<47}  {text}")
    return lines


def endpoint(addr, port):
    if port is None:
        return addr
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


# --------------------------------------------------------------------------
# Packet decoding
# --------------------------------------------------------------------------
def parse_packet(pkt):
    """Turn a scapy packet into a flat dict of the fields we care about."""
    when = datetime.fromtimestamp(float(pkt.time))
    rec = {
        "timestamp": when.isoformat(timespec="milliseconds"),
        "time": when.strftime("%H:%M:%S.%f")[:-3],
        "length": len(pkt),
        "src": "", "dst": "", "protocol": "OTHER",
        "sport": None, "dport": None,
        "service": "", "flags": "", "info": "", "payload": b"",
    }

    # Layer 2/3: ARP has no IP header, so handle it first.
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec["src"], rec["dst"], rec["protocol"] = arp.psrc, arp.pdst, "ARP"
        if arp.op == 1:
            rec["info"] = f"who-has {arp.pdst} tell {arp.psrc}"
        else:
            rec["info"] = f"{arp.psrc} is-at {arp.hwsrc}"
        return rec

    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec["src"], rec["dst"] = ip.src, ip.dst
        rec["protocol"] = IP_PROTOCOLS.get(ip.proto, f"IP-{ip.proto}")
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec["src"], rec["dst"] = ip6.src, ip6.dst
        rec["protocol"] = IP_PROTOCOLS.get(ip6.nh, f"IPv6-{ip6.nh}")
    else:  # some other link-layer frame (STP, LLDP, ...)
        rec["src"] = str(getattr(pkt, "src", ""))
        rec["dst"] = str(getattr(pkt, "dst", ""))
        rec["info"] = safe_text(pkt.summary())
        return rec

    # Layer 4
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.update(protocol="TCP", sport=tcp.sport, dport=tcp.dport,
                   flags=str(tcp.flags))
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.update(protocol="UDP", sport=udp.sport, dport=udp.dport)
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        rec["info"] = ICMP_TYPES.get(icmp.type, f"type {icmp.type}")

    if rec["sport"] is not None:
        rec["service"] = (SERVICES.get(rec["dport"])
                          or SERVICES.get(rec["sport"]) or "")

    # Layer 7: DNS, HTTP, or just raw bytes
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns = pkt[DNS]
        name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        rec["service"] = "DNS"
        rec["info"] = safe_text(f"{'response' if dns.qr else 'query'} for {name}")
        rec["payload"] = bytes(dns)
    elif pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        rec["payload"] = payload
        if payload.startswith(HTTP_STARTS):
            first_line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
            rec["service"] = "HTTP"
            rec["info"] = safe_text(first_line[:100])

    return rec


def matches_protocol(rec, wanted):
    if wanted == "all":
        return True
    if wanted == "dns":
        return rec["service"] == "DNS"
    if wanted == "http":
        return rec["service"] == "HTTP"
    return rec["protocol"].lower() == wanted


# --------------------------------------------------------------------------
# Output: console, log file, statistics
# --------------------------------------------------------------------------
def print_record(rec, args, use_color):
    proto = rec["protocol"]
    shown = f"{proto:<6}"
    if use_color and proto in COLORS:
        shown = f"{COLORS[proto]}{shown}{RESET}"

    extras = [rec["service"]]
    if rec["flags"]:
        extras.append(f"flags={rec['flags']}")
    extras.append(rec["info"])
    extra_text = " | ".join(e for e in extras if e)

    src = endpoint(rec["src"], rec["sport"])
    dst = endpoint(rec["dst"], rec["dport"])
    print(f"[{rec['time']}] {shown} {src:<22} -> {dst:<22} "
          f"{rec['length']:>5}B  {extra_text}")

    payload = rec["payload"]
    if payload and not args.no_payload:
        if args.hex:
            print(f"    payload ({len(payload)} bytes):")
            print("\n".join(hexdump(payload, args.payload_bytes)))
        else:
            print(f"    payload ({len(payload)} bytes): "
                  f"{ascii_preview(payload, args.payload_bytes)}")


class PacketLogger:
    """Writes one row per packet to a .csv or .jsonl file."""

    FIELDS = ["timestamp", "length", "src", "dst", "protocol", "sport",
              "dport", "service", "flags", "info", "payload_len", "payload_hex"]

    def __init__(self, path, payload_bytes):
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".csv", ".jsonl"):
            raise ValueError("--log file must end in .csv or .jsonl")
        self.payload_bytes = payload_bytes
        self.file = open(path, "w", newline="", encoding="utf-8")
        self.writer = None
        if ext == ".csv":
            self.writer = csv.DictWriter(self.file, fieldnames=self.FIELDS)
            self.writer.writeheader()

    @staticmethod
    def _csv_safe(value):
        # Captured data is attacker-controlled: stop spreadsheet formula injection.
        if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
            return "'" + value
        return value

    def write(self, rec):
        row = {k: rec[k] for k in self.FIELDS[:10]}
        row["payload_len"] = len(rec["payload"])
        row["payload_hex"] = rec["payload"][:self.payload_bytes].hex()
        if self.writer:
            self.writer.writerow({k: self._csv_safe(v) for k, v in row.items()})
        else:
            self.file.write(json.dumps(row) + "\n")
        self.file.flush()

    def close(self):
        self.file.close()


class Stats:
    def __init__(self):
        self.total = 0
        self.bytes = 0
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()
        self.services = Counter()

    def update(self, rec):
        self.total += 1
        self.bytes += rec["length"]
        self.protocols[rec["protocol"]] += 1
        self.sources[rec["src"]] += 1
        self.destinations[rec["dst"]] += 1
        if rec["service"]:
            self.services[rec["service"]] += 1

    @staticmethod
    def _fmt(counter, n=5):
        return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n)) or "-"

    def report(self):
        print("\n" + "=" * 60)
        print(" Capture summary")
        print("=" * 60)
        print(f" Packets : {self.total}")
        print(f" Bytes   : {self.bytes}")
        if self.total:
            share = ", ".join(f"{p} {c / self.total:.0%}"
                              for p, c in self.protocols.most_common())
            print(f" Protocols        : {share}")
            print(f" Services         : {self._fmt(self.services)}")
            print(f" Top sources      : {self._fmt(self.sources)}")
            print(f" Top destinations : {self._fmt(self.destinations)}")
        print("=" * 60)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def list_interfaces():
    print("Available interfaces:")
    for iface in conf.ifaces.values():
        name = getattr(iface, "name", str(iface))
        ip = getattr(iface, "ip", "") or ""
        desc = getattr(iface, "description", "") or ""
        print(f"  {name:<24} {ip:<16} {desc}")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Basic network sniffer (CodeAlpha Cyber Security Task 1)")
    src = p.add_argument_group("capture source")
    src.add_argument("-i", "--iface", help="interface to sniff on (default: scapy's default)")
    src.add_argument("-r", "--read", metavar="PCAP", help="read packets from a .pcap file instead of sniffing live")
    src.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit")

    flt = p.add_argument_group("filtering")
    flt.add_argument("-c", "--count", type=int, default=0, help="stop after N matching packets (0 = unlimited)")
    flt.add_argument("-t", "--timeout", type=int, default=None, help="stop live capture after N seconds")
    flt.add_argument("-p", "--protocol", choices=PROTOCOL_CHOICES, default="all", help="only show this protocol")
    flt.add_argument("-f", "--filter", metavar="BPF", help="BPF capture filter for live capture, e.g. 'tcp port 80'")

    out = p.add_argument_group("output")
    out.add_argument("--hex", action="store_true", help="show payload as a hex dump instead of ASCII")
    out.add_argument("--no-payload", action="store_true", help="do not show payload previews")
    out.add_argument("--payload-bytes", type=int, default=64, help="max payload bytes to show/log (default 64)")
    out.add_argument("--pcap", metavar="FILE", help="also save matching packets to a .pcap file (open it in Wireshark)")
    out.add_argument("--log", metavar="FILE", help="log packet metadata to a .csv or .jsonl file")
    out.add_argument("--no-color", action="store_true", help="disable coloured output")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.list_interfaces:
        list_interfaces()
        return 0

    if os.name == "nt":
        os.system("")  # enables ANSI colours in the Windows console
    use_color = (not args.no_color and sys.stdout.isatty()
                 and "NO_COLOR" not in os.environ)

    stats = Stats()
    try:
        logger = PacketLogger(args.log, args.payload_bytes) if args.log else None
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    pcap_writer = PcapWriter(args.pcap, sync=True) if args.pcap else None

    def handle(pkt):
        rec = parse_packet(pkt)
        if not matches_protocol(rec, args.protocol):
            return
        stats.update(rec)
        print_record(rec, args, use_color)
        if pcap_writer:
            pcap_writer.write(pkt)
        if logger:
            logger.write(rec)

    kwargs = dict(prn=handle, store=False,
                  stop_filter=lambda _pkt: bool(args.count) and stats.total >= args.count)

    if args.read:
        if args.filter:
            print("note: --filter (BPF) only applies to live capture; use --protocol for pcap files")
        kwargs["offline"] = args.read
        print(f"Reading packets from {args.read} ... (Ctrl+C to stop)\n")
    else:
        kwargs.update(iface=args.iface, filter=args.filter, timeout=args.timeout)
        print(f"Sniffing on {args.iface or conf.iface} ... (Ctrl+C to stop)\n")

    exit_code = 0
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        pass
    except (OSError, Scapy_Exception) as exc:
        exit_code = 1
        print(f"\ncapture failed: {exc}", file=sys.stderr)
        if "permission" in str(exc).lower() or "not permitted" in str(exc).lower():
            print("hint: packet capture needs elevated rights - use sudo on Linux/macOS, "
                  "or an Administrator terminal on Windows (with Npcap installed).",
                  file=sys.stderr)
    finally:
        if pcap_writer:
            pcap_writer.close()
        if logger:
            logger.close()

    stats.report()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
