"""Fit the Isolation Forest anomaly model on benign feature vectors.

    python -m uninet.training.train_anomaly                    # synthetic benign
    python -m uninet.training.train_anomaly --dataset tii      # TII-SSRC-23 benign

Writes ``models/<anomaly_model>`` (path from config).
"""
from __future__ import annotations

import argparse

import numpy as np

from uninet.config import load_settings
from uninet.detection.anomaly_model import AnomalyModel
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.training._samples import build_samples


def _synthetic_benign_vectors(n_variants: int = 12) -> list[np.ndarray]:
    vectors: list[np.ndarray] = []
    for seed in range(n_variants):
        src = SyntheticSource(seed=1000 + seed)
        benign_hosts = {h for h, t in src.labels.items() if t == ThreatType.BENIGN}
        samples = build_samples(src.collect(), host_labels=src.labels)
        vectors += [
            s.features.as_array() for s in samples if s.host in benign_hosts
        ]
    return vectors


def _tii_benign_vectors(limit: int) -> list[np.ndarray]:
    from uninet.datasets.tii_ssrc23 import load_tii_ssrc23

    recs, labels = load_tii_ssrc23(limit=limit)
    samples = build_samples(recs, flow_labels=labels)
    return [s.features.as_array() for s in samples if s.label == ThreatType.BENIGN]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", choices=["synthetic", "tii"], default="synthetic")
    p.add_argument("--limit", type=int, default=50000, help="max TII rows")
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)

    settings = load_settings()
    if args.dataset == "tii":
        vectors = _tii_benign_vectors(args.limit)
    else:
        vectors = _synthetic_benign_vectors()

    if len(vectors) < 5:
        print(f"not enough benign windows to train ({len(vectors)})")
        return 1

    model = AnomalyModel().fit(np.vstack(vectors))
    out = args.out or settings.model_path_anomaly
    model.save(out)
    print(f"trained on {len(vectors)} benign windows -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
