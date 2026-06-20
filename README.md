# CodeAlpha_NetworkSniffer

A basic Python network sniffer built for the CodeAlpha Cyber Security Internship — Task 1.

## What it does

This tool captures live network packets on a chosen interface and prints, for each packet:

- Timestamp
- Protocol (TCP / UDP / ICMP / OTHER)
- Source IP and port
- Destination IP and port
- Packet length
- (optional, with `-v`) a printable preview of the raw payload

It's a learning tool for understanding how data flows across a network and the basic structure of common protocols (IP, TCP, UDP, ICMP).

## How it works

The script uses [Scapy](https://scapy.net/) to open a raw socket and capture packets as they pass through a network interface. Each captured packet is parsed layer by layer:

1. Check for an IP (or IPv6) layer to get source/destination addresses.
2. Check for a TCP or UDP layer to get port numbers.
3. Check for a Raw layer to extract any payload bytes.
4. Print a clean, readable summary line per packet.

## Requirements

- Linux (uses raw sockets — needs root privileges)
- Python 3.8+
- Scapy

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run with root privileges (required to open a raw socket):

```bash
sudo python3 sniffer.py
```

### Options

| Flag | Description | Example |
|------|-------------|---------|
| `-i`, `--iface` | Network interface to sniff on | `-i eth0` |
| `-c`, `--count` | Number of packets to capture (0 = unlimited) | `-c 50` |
| `-f`, `--filter` | BPF filter syntax | `-f "tcp port 80"` |
| `-v`, `--verbose` | Show a printable payload preview | `-v` |

### Examples

Capture all traffic until you press Ctrl+C:
```bash
sudo python3 sniffer.py
```

Capture 50 packets on a specific interface:
```bash
sudo python3 sniffer.py -i eth0 -c 50
```

Capture only HTTP traffic with payload preview:
```bash
sudo python3 sniffer.py -f "tcp port 80" -v
```

Capture only DNS traffic:
```bash
sudo python3 sniffer.py -f "udp port 53" -v
```

## Sample Output

```
============================================================
 Basic Network Sniffer — CodeAlpha Cyber Security Task 1
============================================================
 Interface : eth0
 Filter    : (none — capturing all traffic)
 Count     : unlimited (Ctrl+C to stop)
------------------------------------------------------------
[14:32:10] TCP   192.168.1.10:52344  ->  142.250.74.46:443  len=66
[14:32:10] UDP   192.168.1.10:53211  ->  192.168.1.1:53  len=70
[14:32:11] ICMP  192.168.1.10  ->  8.8.8.8  len=98
```

## ⚠️ Ethical / Legal Notice

This tool is for **educational purposes only**. Only run it on networks and devices you own or have explicit permission to monitor. Capturing traffic on networks without authorization is illegal in most jurisdictions and violates typical acceptable-use policies.

## What I learned

- How raw packets are structured across the IP, TCP/UDP, and application layers.
- How to use Scapy for live packet capture and BPF-style filtering.
- The difference between connection-oriented (TCP) and connectionless (UDP) traffic at the packet level.
- Why packet sniffing requires elevated privileges, and the security implications of unencrypted protocols (visible payloads).

## Disclaimer

Built as part of the CodeAlpha Cyber Security Internship (Task 1: Basic Network Sniffer).

