"""Prepare local datasets.

    python scripts/prepare_data.py --synthetic     # write a synthetic flow CSV
    python scripts/prepare_data.py --check-tii      # verify TII-SSRC-23 is in place

TII-SSRC-23 must be downloaded manually (licensing): put the flow CSV at
data/raw/tii-ssrc-23/flows.csv  (see uninet/datasets/tii_ssrc23.py).
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from uninet.ingestion.sources.synthetic import SyntheticSource

PROCESSED = ROOT / "data" / "processed"


def write_synthetic_csv(seed: int = 42) -> Path:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    out = PROCESSED / "synthetic_flows.csv"
    src = SyntheticSource(seed=seed)
    cols = ["start_ts", "end_ts", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packets", "bytes", "tcp_flags", "dns_qname", "dns_rcode",
            "tls_sni", "ja3", "label"]
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in src.stream():
            row = r.model_dump()
            row["protocol"] = r.protocol.value
            row["label"] = src.labels.get(r.src_ip, "benign").value if hasattr(
                src.labels.get(r.src_ip, None), "value"
            ) else "benign"
            w.writerow({k: row.get(k, "") for k in cols})
    print(f"wrote {out}")
    return out


def check_tii() -> int:
    from uninet.datasets.tii_ssrc23 import DEFAULT_CSV

    if DEFAULT_CSV.is_file():
        print(f"OK  {DEFAULT_CSV} ({DEFAULT_CSV.stat().st_size / 1e6:.1f} MB)")
        return 0
    print(f"MISSING  {DEFAULT_CSV}\n  Download TII-SSRC-23 and place the flow CSV there.")
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--synthetic", action="store_true")
    p.add_argument("--check-tii", action="store_true")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)

    if args.check_tii:
        return check_tii()
    if args.synthetic:
        write_synthetic_csv(args.seed)
        return 0
    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
