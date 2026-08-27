"""TII-SSRC-23 loader.

The dataset ships both raw PCAP and a labelled flow CSV. We use the flow CSV:
each row -> :class:`FlowRecord` (via ``NetFlowCsvSource`` column mapping) plus a
mapped :class:`ThreatType` label.

Download (manual, ~fill once):
    1. Get "TII-SSRC-23" from IEEE DataPort / Kaggle.
    2. Put the flow CSV at:  data/raw/tii-ssrc-23/flows.csv
    3. Run:  python -m uninet.datasets.tii_ssrc23 --check
"""
from __future__ import annotations

import argparse
from pathlib import Path

from uninet.config import REPO_ROOT
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.netflow import NetFlowCsvSource
from uninet.schemas.flow import FlowRecord

DEFAULT_CSV = REPO_ROOT / "data" / "raw" / "tii-ssrc-23" / "flows.csv"

# TII-SSRC-23 CICFlowMeter-style columns -> FlowRecord fields.
TII_COLUMNS = {
    "src_ip": "Src IP",
    "dst_ip": "Dst IP",
    "src_port": "Src Port",
    "dst_port": "Dst Port",
    "protocol": "Protocol",
    "start_ts": "Timestamp",
    "end_ts": "Timestamp",
    "packets": "Total Fwd Packet",
    "bytes": "Total Length of Fwd Packet",
}

# Dataset traffic-type / label -> UniNet taxonomy.
TII_LABEL_MAP: dict[str, ThreatType] = {
    "benign": ThreatType.BENIGN,
    "background": ThreatType.BENIGN,
    "dos": ThreatType.DDOS,
    "ddos": ThreatType.DDOS,
    "mirai": ThreatType.BOTNET,
    "bruteforce": ThreatType.PORT_SCAN,
    "brute_force": ThreatType.PORT_SCAN,
    "scan": ThreatType.PORT_SCAN,
    "portscan": ThreatType.PORT_SCAN,
    "infiltration": ThreatType.DATA_EXFIL,
    "exfiltration": ThreatType.DATA_EXFIL,
    "c2": ThreatType.C2_BEACON,
    "botnet": ThreatType.BOTNET,
    "dns": ThreatType.DGA,
}

_LABEL_COLUMNS = ("Label", "label", "Attack", "Traffic Type", "Class")


def _map_label(raw: str) -> ThreatType:
    key = (raw or "").strip().lower().replace(" ", "_").replace("-", "_")
    if key in TII_LABEL_MAP:
        return TII_LABEL_MAP[key]
    for frag, tt in TII_LABEL_MAP.items():
        if frag in key:
            return tt
    return ThreatType.UNKNOWN


def load_tii_ssrc23(
    csv_path: str | Path | None = None, limit: int | None = None
) -> tuple[list[FlowRecord], list[ThreatType]]:
    """Return ``(records, labels)`` aligned by index."""
    import csv as _csv

    path = Path(csv_path or DEFAULT_CSV)
    if not path.is_file():
        raise FileNotFoundError(
            f"TII-SSRC-23 flow CSV not found at {path}. See module docstring for setup."
        )

    source = NetFlowCsvSource(path, columns=TII_COLUMNS, source_label="tii-ssrc-23")
    records = source.collect(limit=limit)

    labels: list[ThreatType] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = _csv.DictReader(fh)
        label_col = next((c for c in _LABEL_COLUMNS if c in (reader.fieldnames or [])), None)
        for i, row in enumerate(reader):
            if limit is not None and i >= limit:
                break
            labels.append(_map_label(row.get(label_col, "")) if label_col else ThreatType.UNKNOWN)

    n = min(len(records), len(labels))
    return records[:n], labels[:n]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="TII-SSRC-23 loader sanity check")
    p.add_argument("--csv", default=None)
    p.add_argument("--check", action="store_true")
    p.add_argument("--limit", type=int, default=5000)
    args = p.parse_args(argv)
    try:
        recs, labels = load_tii_ssrc23(args.csv, limit=args.limit)
    except FileNotFoundError as e:
        print(e)
        return 1
    from collections import Counter

    print(f"loaded {len(recs)} flows")
    print("label distribution:", dict(Counter(l.value for l in labels)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
