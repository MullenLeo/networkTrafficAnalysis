import os
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("data/packets.csv", parse_dates=["time"])
df["sport"] = df["sport"].astype("Int64")
df["dport"] = df["dport"].astype("Int64")
os.makedirs("figures", exist_ok=True)

print("\n== Protocol summary ==")
print(df.groupby("proto").agg(packets=("length", "size"),
      bytes=("length", "sum"), mean_len=("length", "mean"),
      first=("time", "min"), last=("time", "max")))

print("\n== Top 10 destinations by bytes ==")
print(df.groupby("dst")["length"].agg(["size", "sum"])
        .sort_values("sum", ascending=False).head(10))

print("\n== Top 10 destination ports ==")
print(df["dport"].value_counts().head(10))

per_sec = df.set_index("time")["length"].resample("1s").agg(["size", "sum"])
per_sec.columns = ["packets", "bytes"]
thr = per_sec["bytes"].mean() + 2 * per_sec["bytes"].std()
spikes = per_sec[per_sec["bytes"] > thr]
print(f"\nSpike threshold: {thr:,.0f} bytes/s, {len(spikes)} spike seconds")

ax = per_sec["bytes"].plot(figsize=(10, 4), title="Traffic volume per second")
ax.axhline(thr, color="red", linestyle="--", label="mean + 2 SD")
ax.set_ylabel("Bytes")
ax.legend()
plt.tight_layout()
plt.savefig("figures/traffic_over_time.png", dpi=150)

top = df.groupby("dst")["length"].sum().sort_values(ascending=False).head(10)
top.plot(kind="barh", figsize=(8, 4), title="Top destinations by bytes").invert_yaxis()
plt.tight_layout()
plt.savefig("figures/top_destinations.png", dpi=150)