import pandas as pd

pd.set_option("display.width", 200)
pd.set_option("display.max_columns", 20)

CFG = {
    "burst_window": "1s", "burst_flows": 20,
    "scan_ports": 15,
    "half_open_flows": 10,
    "upload_bytes": 500_000, "upload_ratio": 5,
    "beacon_min_flows": 6, "beacon_cv": 0.2, "beacon_min_gap_s": 1.0,
}

# Fill these in only after verifying owners with whois
ALLOW_EXACT = {"1.1.1.1"}
ALLOW_PREFIX = ("13.107.",)


def alert(rule, ip, detail, score):
    return {"rule": rule, "remote_ip": ip, "detail": detail, "score": score}


def rule_burst(f):
    out = []
    s = f.sort_values("start").set_index("start")
    for ip, g in s.groupby("remote_ip"):
        peak = int(g["packets"].rolling(CFG["burst_window"]).count().max())
        if peak >= CFG["burst_flows"]:
            out.append(alert("burst", ip, f"{peak} flows in {CFG['burst_window']}", peak))
    return out


def rule_port_scan(f):
    n = f.groupby("remote_ip")["remote_port"].nunique()
    return [alert("port_scan", ip, f"{c} distinct ports", int(c))
            for ip, c in n.items() if c >= CFG["scan_ports"]]


def rule_half_open(f):
    h = f[(f["syn_count"] > 0) & (f["bytes_in"] == 0)]
    c = h.groupby("remote_ip").size()
    return [alert("half_open", ip, f"{n} unanswered SYN flows", int(n))
            for ip, n in c.items() if n >= CFG["half_open_flows"]]


def rule_upload(f):
    m = (f["bytes_out"] > CFG["upload_bytes"]) & (f["out_in_ratio"] > CFG["upload_ratio"])
    g = f[m].groupby("remote_ip").agg(total=("bytes_out", "sum"), flows=("bytes_out", "size"))
    return [alert("upload_heavy", ip, f"{r.total:,} bytes out over {r.flows} flows", int(r.total))
            for ip, r in g.iterrows()]


def rule_beacon(f):
    out = []
    for (ip, port), g in f.groupby(["remote_ip", "remote_port"]):
        if len(g) < CFG["beacon_min_flows"]:
            continue
        gaps = g.sort_values("start")["start"].diff().dt.total_seconds().dropna()
        if gaps.mean() >= CFG["beacon_min_gap_s"] and gaps.std() / gaps.mean() < CFG["beacon_cv"]:
            out.append(alert("beacon", ip, f"port {port}, gap {gaps.mean():.1f}s", len(g)))
    return out


def is_allowed(ip):
    return ip in ALLOW_EXACT or str(ip).startswith(ALLOW_PREFIX)


def run(flows):
    rules = [rule_burst, rule_port_scan, rule_half_open, rule_upload, rule_beacon]
    rows = [a for r in rules for a in r(flows)]
    cols = ["rule", "remote_ip", "detail", "score"]
    alerts = pd.DataFrame(rows, columns=cols)
    alerts["allowlisted"] = alerts["remote_ip"].map(is_allowed)
    return alerts


if __name__ == "__main__":
    flows = pd.read_csv("data/flows.csv", parse_dates=["start", "end"])
    alerts = run(flows)
    print(alerts.sort_values(["rule", "score"], ascending=[True, False]))
    print("\nRaw alerts:", len(alerts))
    print("After allow-list:", int((~alerts["allowlisted"]).sum()))
    alerts.to_csv("data/alerts.csv", index=False)