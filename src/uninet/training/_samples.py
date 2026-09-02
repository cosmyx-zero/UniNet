"""Turn a flat flow log into labelled (features, subgraph) training samples.

Shared by ``train_anomaly.py`` and ``train_rgat.py``. Mirrors the windowing that
``streaming.worker.run_pipeline`` does at inference time, so training and serving
see the same feature/graph construction.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from uninet.detection.threat_types import ThreatType
from uninet.features.extractor import FeatureExtractor, HostWindowFeatures
from uninet.ingestion.flow_parser import local_host_of
from uninet.schemas.flow import FlowRecord
from uninet.tb_graph.burst_builder import BurstBuilder
from uninet.tb_graph.graph_builder import GraphBuilder
from uninet.tb_graph.graph_store import TBGraphStore


@dataclass
class Sample:
    host: str
    window_start: float
    features: HostWindowFeatures
    subgraph: object                 # networkx.MultiDiGraph
    label: ThreatType


def build_samples(
    records: list[FlowRecord],
    *,
    flow_labels: list[ThreatType] | None = None,
    host_labels: dict[str, ThreatType] | None = None,
    window_seconds: float = 60.0,
    gap_seconds: float = 2.0,
    min_flows_per_window: int = 4,
) -> list[Sample]:
    if not records:
        return []

    order = sorted(range(len(records)), key=lambda i: records[i].start_ts)
    records = [records[i] for i in order]
    if flow_labels is not None:
        flow_labels = [flow_labels[i] for i in order]

    bb = BurstBuilder(gap_seconds)
    gb = GraphBuilder()
    fx = FeatureExtractor(window_seconds)
    store = TBGraphStore()

    t0, t_end = records[0].start_ts, records[-1].start_ts
    samples: list[Sample] = []
    ws = t0
    while ws <= t_end:
        we = ws + window_seconds
        idxs = [i for i, r in enumerate(records) if ws <= r.start_ts < we]
        if idxs:
            by_host: dict[str, list[int]] = defaultdict(list)
            for i in idxs:
                by_host[local_host_of(records[i])].append(i)

            for host, hidx in by_host.items():
                if len(hidx) < min_flows_per_window:
                    continue
                hflows = [records[i] for i in hidx]
                bursts = bb.build(hflows, host)
                feats = fx.extract(host, hflows, bursts, ws, we)
                store.merge(gb.build(bursts))
                subgraph = store.subgraph_for_host(host)

                label = _window_label(host, hidx, flow_labels, host_labels)
                samples.append(Sample(host, ws, feats, subgraph, label))
        ws = we
    return samples


def _window_label(
    host: str,
    hidx: list[int],
    flow_labels: list[ThreatType] | None,
    host_labels: dict[str, ThreatType] | None,
) -> ThreatType:
    if host_labels is not None:
        return host_labels.get(host, ThreatType.BENIGN)
    if flow_labels is not None:
        counts = Counter(flow_labels[i] for i in hidx)
        counts.pop(ThreatType.BENIGN, None)
        if counts:
            return counts.most_common(1)[0][0]
    return ThreatType.BENIGN
