#!/usr/bin/env python3
"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship — Task 1

Captures live network packets and displays key info:
source/destination IP, protocol, ports, and a payload preview.

Requires root/sudo privileges to open a raw socket.
Usage:
    sudo python3 sniffer.py
    sudo python3 sniffer.py -i eth0 -c 50
    sudo python3 sniffer.py -f "tcp port 80"
"""

import argparse
import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, conf


def get_protocol_name(pkt):
    """Return a human-readable protocol name for the packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def format_payload(pkt, max_len=64):
    """Return a printable, truncated preview of the raw payload, if any."""
    if not pkt.haslayer(Raw):
        return ""
    raw_bytes = bytes(pkt[Raw].load)
    printable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:max_len]
    )
    suffix = "..." if len(raw_bytes) > max_len else ""
    return printable + suffix


def process_packet(pkt, verbose=False):
    """Callback invoked by scapy for every captured packet."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]

    if ip_layer is None:
        # Non-IP traffic (e.g. ARP) — skip for this basic sniffer
        return

    proto = get_protocol_name(pkt)
    src = ip_layer.src
    dst = ip_layer.dst

    src_port = dst_port = None
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    port_info = f":{src_port} -> :{dst_port}" if src_port else ""

    length = len(pkt)

    print(f"[{timestamp}] {proto:<5} {src}{port_info and ' ' + str(src_port) or ''}"
          f"  ->  {dst}{(' ' + str(dst_port)) if dst_port else ''}  "
          f"len={length}")

    if verbose:
        payload_preview = format_payload(pkt)
        if payload_preview:
            print(f"          payload: {payload_preview}")


def main():
    parser = argparse.ArgumentParser(description="Basic Python Network Sniffer")
    parser.add_argument("-i", "--iface", default=None,
                         help="Network interface to sniff on (default: scapy auto-selects)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = run until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                         help="BPF filter, e.g. 'tcp port 80' or 'udp port 53'")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show a printable preview of packet payload")
    args = parser.parse_args()

    iface = args.iface or conf.iface
    print("=" * 60)
    print(" Basic Network Sniffer — CodeAlpha Cyber Security Task 1")
    print("=" * 60)
    print(f" Interface : {iface}")
    print(f" Filter    : {args.filter or '(none — capturing all traffic)'}")
    print(f" Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 60)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter or None,
            prn=lambda pkt: process_packet(pkt, verbose=args.verbose),
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Try running with sudo:")
        print("    sudo python3 sniffer.py")
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")


if __name__ == "__main__":
    main()
