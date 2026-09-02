"""Detection metrics.

    python -m uninet.eval.metrics                 # synthetic scenarios
    python -m uninet.eval.metrics --dataset tii   # TII-SSRC-23

Reports per-host detection (did we flag the malicious hosts?) and, where ground
truth is per class, a confusion matrix over the threat taxonomy. Numbers here are
the ones to quote - not the marketing-slide figures.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict

from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.streaming.worker import run_pipeline


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def evaluate_synthetic(seeds: int = 8) -> dict:
    settings = load_settings()
    detector = Detector.from_settings(settings)

    per_class_tp: Counter[str] = Counter()
    per_class_fn: Counter[str] = Counter()
    confusion: dict[str, Counter] = defaultdict(Counter)
    fp = 0
    benign_hosts = mal_hosts = 0

    for seed in range(seeds):
        src = SyntheticSource(seed=seed)
        truth = src.labels
        result = run_pipeline(src, settings, detector=detector)
        flagged = {a.src_host: a.threat_type for a in result.alerts}

        for host, actual in truth.items():
            if actual == ThreatType.BENIGN:
                benign_hosts += 1
                if host in flagged:
                    fp += 1
                continue
            mal_hosts += 1
            if host in flagged:
                per_class_tp[actual.value] += 1
                confusion[actual.value][flagged[host].value] += 1
            else:
                per_class_fn[actual.value] += 1
                confusion[actual.value]["(missed)"] += 1

    tp = sum(per_class_tp.values())
    fn = sum(per_class_fn.values())
    p, r, f = _prf(tp, fp, fn)
    return {
        "seeds": seeds,
        "malicious_hosts": mal_hosts,
        "benign_hosts": benign_hosts,
        "detected": tp,
        "missed": fn,
        "false_positives": fp,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f, 4),
        "fp_rate": round(fp / benign_hosts, 4) if benign_hosts else 0.0,
        "per_class_recall": {
            k: round(per_class_tp[k] / (per_class_tp[k] + per_class_fn[k]), 3)
            for k in sorted(set(per_class_tp) | set(per_class_fn))
        },
        "confusion": {k: dict(v) for k, v in confusion.items()},
    }


def evaluate_tii(limit: int) -> dict:
    from uninet.datasets.tii_ssrc23 import load_tii_ssrc23
    from uninet.ingestion.sources.base import FlowSource

    settings = load_settings()
    recs, labels = load_tii_ssrc23(limit=limit)

    class _Src(FlowSource):
        name = "tii"

        def stream(self):
            yield from recs

    result = run_pipeline(_Src(), settings, detector=Detector.from_settings(settings))
    # per-flow truth -> per-host majority malicious label
    host_truth: dict[str, Counter] = defaultdict(Counter)
    from uninet.ingestion.flow_parser import local_host_of

    for rec, lab in zip(recs, labels):
        host_truth[local_host_of(rec)][lab] += 1

    flagged = {a.src_host: a.threat_type for a in result.alerts}
    tp = fp = fn = 0
    for host, c in host_truth.items():
        c.pop(ThreatType.BENIGN, None)
        malicious = bool(c)
        if host in flagged and malicious:
            tp += 1
        elif host in flagged and not malicious:
            fp += 1
        elif host not in flagged and malicious:
            fn += 1
    p, r, f = _prf(tp, fp, fn)
    return {"flows": len(recs), "tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", choices=["synthetic", "tii"], default="synthetic")
    p.add_argument("--seeds", type=int, default=8)
    p.add_argument("--limit", type=int, default=50000)
    args = p.parse_args(argv)

    import json

    if args.dataset == "tii":
        try:
            report = evaluate_tii(args.limit)
        except FileNotFoundError as e:
            print(e)
            return 1
    else:
        report = evaluate_synthetic(args.seeds)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
