# CodeAlpha_BasicNetworkSniffer

A command-line network sniffer written in Python with [Scapy](https://scapy.net/).
Built for **Task 1 – Basic Network Sniffer** of the CodeAlpha Cyber Security Internship.

It captures packets from a live interface (or replays a `.pcap` file), decodes them layer by layer and shows who is talking to whom, over which protocol, and what is inside the packet.

## Features

- Live capture on any interface, or offline analysis of `.pcap` files (`-r`)
- Decodes **Ethernet → IPv4 / IPv6 → TCP / UDP / ICMP / ARP → DNS / HTTP**
- Shows source/destination IP and port, protocol, packet size, TCP flags and a **payload preview** (ASCII or hex dump)
- Detects common services by port (HTTP, HTTPS, SSH, FTP, DNS, …) and reads DNS query names and HTTP request lines from the payload
- Filters: BPF capture filter (`-f`), protocol filter (`-p`), packet count (`-c`), timeout (`-t`)
- Saves captures to `.pcap` (open in Wireshark) and metadata to `.csv` / `.jsonl`
- Prints a summary at the end: protocol share, top talkers, services seen
- Safe output handling: control characters in captured data are neutralised (no terminal-escape injection) and CSV cells are protected against formula injection

## Setup

Requires Python 3.8+ and packet-capture privileges.

```bash
git clone https://github.com/<your-username>/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
pip install -r requirements.txt
```

| OS | Extra steps |
|----|-------------|
| **Windows** | Install [Npcap](https://npcap.com/) (tick *WinPcap API-compatible mode*) and run the terminal **as Administrator** |
| **Linux** | `libpcap` is usually present; run with `sudo` (if you use a virtualenv: `sudo venv/bin/python sniffer.py`) |
| **macOS** | Run with `sudo` (main interface is usually `en0`) |

## Usage

```bash
python sniffer.py --list-interfaces            # find your interface name
sudo python sniffer.py -i eth0                 # sniff everything (Ctrl+C to stop)
sudo python sniffer.py -i eth0 -c 50           # stop after 50 packets
sudo python sniffer.py -i eth0 -p dns          # only DNS
sudo python sniffer.py -i eth0 -f "tcp port 80" --hex
sudo python sniffer.py -i eth0 --pcap capture.pcap --log capture.csv
python sniffer.py -r samples/sample_traffic.pcap   # no root needed for pcap files
```

| Option | Meaning |
|--------|---------|
| `-i, --iface` | Interface to sniff on |
| `-r, --read` | Read from a `.pcap` file instead of sniffing live |
| `-c, --count` | Stop after N matching packets |
| `-t, --timeout` | Stop live capture after N seconds |
| `-p, --protocol` | `all`, `tcp`, `udp`, `icmp`, `arp`, `dns`, `http` |
| `-f, --filter` | BPF filter applied during live capture |
| `--hex` / `--no-payload` | Hex dump instead of ASCII / hide payloads |
| `--payload-bytes N` | Max payload bytes shown or logged (default 64) |
| `--pcap FILE` | Save matching packets to a `.pcap` |
| `--log FILE` | Log metadata to `.csv` or `.jsonl` |
| `--no-color` | Disable coloured output |

## Sample output

`python sniffer.py -r samples/sample_traffic.pcap` (synthetic demo traffic):

```
[17:00:33.009] UDP    192.168.1.20:53211     -> 192.168.1.1:53            71B  DNS | query for example.com
    payload (29 bytes): .............example.com.....
[17:00:33.694] TCP    192.168.1.20:40100     -> 93.184.216.34:80         119B  HTTP | flags=PA | GET /index.html HTTP/1.1
    payload (65 bytes): GET /index.html HTTP/1.1..Host: example.com..User-Agent: demo......
[17:00:34.242] TCP    192.168.1.20:40300     -> 203.0.113.7:21            70B  FTP | flags=PA
    payload (16 bytes): USER anonymous..
[17:00:34.379] TCP    192.168.1.20:40300     -> 203.0.113.7:21            78B  FTP | flags=PA
    payload (24 bytes): PASS guest@example.com..
[17:00:34.516] ICMP   192.168.1.20           -> 8.8.8.8                   50B  echo-request
[17:00:34.790] TCP    [fe80::1]:51000        -> [2001:db8::1]:443         74B  HTTPS | flags=S

============================================================
 Capture summary
============================================================
 Packets : 18
 Bytes   : 1275
 Protocols        : TCP 61%, UDP 17%, ARP 11%, ICMP 11%
 Services         : HTTP (5), HTTPS (3), FTP (3), DNS (2), NTP (1)
 Top sources      : 192.168.1.20 (11), 192.168.1.1 (2), 93.184.216.34 (2), ...
============================================================
```

> Add your own screenshots of a live capture to a `docs/` folder and link them here.

## How it works

Every packet is a set of nested envelopes. The sniffer peels them off one by one:

```
Ethernet frame      MAC addresses
 └─ IP packet       source / destination IP, protocol number
     └─ TCP / UDP   ports, TCP flags
         └─ payload DNS query, HTTP request, TLS bytes, ...
```

**TCP flags** shown in the output: `S` SYN (start connection), `A` ACK, `P` PSH (data), `F` FIN (close), `R` RST (reset). A normal connection starts `S → SA → A`.

**Why payloads matter:** the FTP and HTTP examples above are readable because those protocols are unencrypted, so anyone on the same network segment can read credentials and pages. HTTPS payloads appear as unreadable bytes because they are encrypted with TLS. That contrast is the main security takeaway of this task.

**Limits:** the service label is a best guess from port numbers (plus HTTP/DNS content detection). On switched networks you normally only see your own traffic plus broadcasts. Encrypted traffic can be counted but not read.

## Project structure

```
sniffer.py                 main program (capture, decode, display, logging)
requirements.txt
tools/make_sample_pcap.py  generates the synthetic demo capture
samples/sample_traffic.pcap
tests/test_parser.py       unit tests for the packet decoder
```

Run the tests: `python -m unittest discover tests`

## Ethical use

Only sniff networks you own or have written permission to monitor. Capturing other people's traffic without authorisation is illegal in many countries.

## Author

Santhosh S — CodeAlpha Cyber Security Internship

## License

MIT
