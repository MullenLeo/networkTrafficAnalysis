import ipaddress
import pandas as pd

df = pd.read_csv("data/packets.csv", parse_dates=["time"])
df["sport"] = df["sport"].astype("Int64")
df["dport"] = df["dport"].astype("Int64")

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

df["src_private"] = df["src"].map(is_private)
df["dst_private"] = df["dst"].map(is_private)
df["direction"] = "other"
df.loc[df.src_private & ~df.dst_private, "direction"] = "outbound"
df.loc[~df.src_private & df.dst_private, "direction"] = "inbound"

df["remote_ip"] = df["dst"].where(df.direction == "outbound", df["src"])
df["remote_port"] = df["dport"].where(df.direction == "outbound", df["sport"])

print(df["direction"].value_counts())
print(df.groupby(["direction", "remote_ip"])["length"].sum()
        .sort_values(ascending=False).head(10))
print(df.groupby("remote_port")["length"].agg(["size", "sum"])
        .sort_values("sum", ascending=False).head(10))
df.to_csv("data/packets_enriched.csv", index=False)

