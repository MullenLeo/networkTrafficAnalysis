import pandas as pd

df = pd.read_csv("data/packets_enriched.csv", parse_dates=["time"])
df = df[df.direction.isin(["outbound", "inbound"])].copy()
df = df.sort_values("time")

out = df.direction == "outbound"
df["local_ip"] = df["src"].where(out, df["dst"])
df["local_port"] = df["sport"].where(out, df["dport"])
df["bytes_out"] = df["length"].where(out, 0)
df["bytes_in"] = df["length"].where(~out, 0)
df["pure_syn"] = df["flags"] == "S"

key = ["local_ip", "local_port", "remote_ip", "remote_port", "proto"]
g = df.groupby(key, dropna=False)

flows = g.agg(start=("time", "min"), end=("time", "max"),
              packets=("length", "size"), bytes=("length", "sum"),
              bytes_out=("bytes_out", "sum"), bytes_in=("bytes_in", "sum"),
              syn_count=("pure_syn", "sum")).reset_index()

flows["duration_s"] = (flows["end"] - flows["start"]).dt.total_seconds()
flows["pkts_per_s"] = flows["packets"] / flows["duration_s"].clip(lower=0.001)
flows["out_in_ratio"] = flows["bytes_out"] / flows["bytes_in"].clip(lower=1)

iat = g["time"].apply(lambda s: s.diff().dt.total_seconds().mean())
flows["mean_iat_s"] = iat.values

print(f"{len(flows)} flows from {len(df)} packets")
print(flows.sort_values("bytes", ascending=False).head(10)
      [["remote_ip", "remote_port", "packets", "bytes", "duration_s", "out_in_ratio"]])
print(flows.groupby("remote_ip").size().sort_values(ascending=False).head(10))
flows.to_csv("data/flows.csv", index=False)