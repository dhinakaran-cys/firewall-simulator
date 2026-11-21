"""Run once:  python make_sample_pcap.py   ->  creates sample.pcap (60 random packets)."""
from scapy.all import wrpcap
from firewall.packets import build, random_packet

packets = []
for _ in range(60):
    p = random_packet()
    packets.append(build(p["src"], p["dst"], p["proto"], p["dport"]))
wrpcap("sample.pcap", packets)
print("Wrote sample.pcap with", len(packets), "packets")
