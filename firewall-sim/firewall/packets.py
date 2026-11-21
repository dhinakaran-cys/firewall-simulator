"""
packets.py - the ONLY file that uses Scapy.

Scapy lets us build and read real network packets. We use it for three jobs:
  build()      make a genuine IP/TCP (or UDP/ICMP) packet from form values
  parse()      read a Scapy packet and pull out the 4 fields the firewall cares about
  read_pcap()  load packets recorded earlier (e.g. from Wireshark)

A packet is layered like a sandwich:  IP (who -> whom)  /  TCP or UDP (which port)  /  data
Firewalls mostly just read those headers.
"""
import random
from scapy.all import ICMP, IP, TCP, UDP, rdpcap


def build(src: str, dst: str, proto: str, dport: int | None):
    """Create a real Scapy packet. The '/' operator stacks layers."""
    ip = IP(src=src, dst=dst)
    if proto == "TCP":
        return ip / TCP(sport=random.randint(1024, 65535), dport=dport or 80)
    if proto == "UDP":
        return ip / UDP(sport=random.randint(1024, 65535), dport=dport or 53)
    return ip / ICMP()


def parse(pkt) -> dict | None:
    """Scapy packet -> plain dict. Returns None for non-IP traffic (e.g. ARP)."""
    if IP not in pkt:
        return None
    if TCP in pkt:
        proto, dport = "TCP", pkt[TCP].dport
    elif UDP in pkt:
        proto, dport = "UDP", pkt[UDP].dport
    elif ICMP in pkt:
        proto, dport = "ICMP", None
    else:
        proto, dport = "OTHER", None
    return {"src": pkt[IP].src, "dst": pkt[IP].dst, "proto": proto, "dport": dport}


def read_pcap(path: str) -> list[dict]:
    """Load a .pcap file and parse every IP packet inside."""
    parsed = (parse(p) for p in rdpcap(path))
    return [p for p in parsed if p]


# ---- synthetic traffic for demos -----------------------------------------
_SOURCES = ["192.168.1.10", "192.168.1.25", "10.0.0.7", "198.51.100.23",
            "203.0.113.5", "203.0.113.77", "45.33.32.156", "8.8.4.4"]
_DESTS = ["192.168.1.1", "192.168.1.50", "10.0.0.1"]
_SERVICES = [("TCP", 443), ("TCP", 80), ("TCP", 22), ("TCP", 23), ("TCP", 3389),
             ("TCP", 3306), ("UDP", 53), ("UDP", 123), ("ICMP", None)]


def random_packet() -> dict:
    proto, dport = random.choice(_SERVICES)
    return {"src": random.choice(_SOURCES), "dst": random.choice(_DESTS),
            "proto": proto, "dport": dport}
