import sys
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, ICMP


def parse(path):
    rows = []
    for pkt in rdpcap(path):
        row = {"time": float(pkt.time), "length": len(pkt),
               "src": None, "dst": None, "proto": "OTHER",
               "sport": None, "dport": None, "flags": None}
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is not None:
            row["src"], row["dst"] = ip.src, ip.dst
            if pkt.haslayer(TCP):
                t = pkt[TCP]
                row.update(proto="TCP", sport=t.sport, dport=t.dport, flags=str(t.flags))
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                row.update(proto="UDP", sport=u.sport, dport=u.dport)
            elif pkt.haslayer(ICMP):
                row["proto"] = "ICMP"
            if pkt.haslayer(DNS):
                row["proto"] = "DNS"
        rows.append(row)
    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["time"], unit="s")
    return df


if __name__ == "__main__":
    df = parse(sys.argv[1])
    print(df.shape)
    print(df.head())
    print(df["proto"].value_counts())
    df.to_csv("data/packets.csv", index=False)