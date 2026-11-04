from scapy.all import rdpcap
import sys

packets = rdpcap(sys.argv[1])
print(f"Loaded {len(packets)} packets")
print(packets[0].summary())