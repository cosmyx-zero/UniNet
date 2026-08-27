"""Per-(host, window) feature extraction.

Produces a fixed-order numeric vector (``FEATURE_KEYS``) consumed by the anomaly
model and the rules, plus a richer :class:`HostWindowFeatures` object that keeps
the human-readable context (top domains, port spread, ...) for evidence and the
dashboard.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from uninet.ingestion.flow_parser import direction_of, peer_of
from uninet.schemas.burst import Direction, TrafficBurst
from uninet.schemas.flow import FlowRecord
from uninet.utils import (
    coefficient_of_variation,
    mean,
    periodicity_score,
    registrable_label,
    safe_ratio,
    shannon_entropy,
)

# Fixed order - the anomaly model depends on this. Append only.
FEATURE_KEYS: list[str] = [
    "flow_count",
    "byte_count",
    "packet_count",
    "active_seconds",
    "flows_per_second",
    "packets_per_second",
    "bytes_per_second",
    "mean_flow_bytes",
    "mean_flow_packets",
    "mean_flow_duration",
    "unique_peers",
    "unique_dst_ports",
    "dst_port_dispersion",
    "out_in_byte_ratio",
    "out_in_flow_ratio",
    "dns_query_count",
    "unique_domain_count",
    "nxdomain_ratio",
    "mean_domain_entropy",
    "max_domain_entropy",
    "tls_flow_ratio",
    "unique_ja3",
    "burst_count",
    "mean_burst_gap",
    "burst_gap_cov",
    "max_inter_burst_periodicity",
    "mean_burst_bytes",
    "syn_only_ratio",
]


@dataclass
class HostWindowFeatures:
    host: str
    window_start: float
    window_end: float
    vector: dict[str, float] = field(default_factory=dict)

    peers: list[str] = field(default_factory=list)
    top_domains: list[str] = field(default_factory=list)
    dst_ports: list[int] = field(default_factory=list)
    bursts: list[TrafficBurst] = field(default_factory=list)
    inter_burst_periodicity: float = 0.0

    def as_array(self) -> np.ndarray:
        return np.array([self.vector.get(k, 0.0) for k in FEATURE_KEYS], dtype=float)


class FeatureExtractor:
    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = float(window_seconds)

    def extract(
        self,
        host: str,
        flows: list[FlowRecord],
        bursts: list[TrafficBurst],
        window_start: float | None = None,
        window_end: float | None = None,
    ) -> HostWindowFeatures:
        if not flows:
            return HostWindowFeatures(host, window_start or 0.0, window_end or 0.0)

        ws = window_start if window_start is not None else min(f.start_ts for f in flows)
        we = window_end if window_end is not None else max(f.end_ts for f in flows)
        # Rates use the *active* span (first->last flow), not the nominal window
        # width - a 7s flood inside a 300s window is still a flood.
        active_span = max(
            max(f.end_ts for f in flows) - min(f.start_ts for f in flows), 1.0
        )
        span = active_span

        out = [f for f in flows if direction_of(f, host) == Direction.OUTBOUND]
        inb = [f for f in flows if direction_of(f, host) == Direction.INBOUND]

        peers = sorted({peer_of(f, host) for f in flows})
        dst_ports = [f.dst_port for f in out if f.dst_port]
        uniq_ports = sorted(set(dst_ports))

        dns_flows = [f for f in flows if f.is_dns and f.dns_qname]
        domains = [f.dns_qname for f in dns_flows if f.dns_qname]
        uniq_domains = sorted(set(domains))
        nx = sum(1 for f in dns_flows if f.dns_rcode == 3)
        entropies = [shannon_entropy(registrable_label(d)) for d in uniq_domains]

        tls_flows = [f for f in flows if f.is_tls]
        ja3s = {f.ja3 for f in flows if f.ja3}

        syn_only = sum(1 for f in flows if f.tcp_flags and set(f.tcp_flags.upper()) <= {"S"})

        burst_starts = sorted(b.start_ts for b in bursts)
        burst_gaps = list(np.diff(burst_starts)) if len(burst_starts) > 1 else []

        v: dict[str, float] = {
            "flow_count": float(len(flows)),
            "byte_count": float(sum(f.bytes for f in flows)),
            "packet_count": float(sum(f.packets for f in flows)),
            "active_seconds": active_span,
            "flows_per_second": len(flows) / span,
            "packets_per_second": sum(f.packets for f in flows) / span,
            "bytes_per_second": sum(f.bytes for f in flows) / span,
            "mean_flow_bytes": mean(f.bytes for f in flows),
            "mean_flow_packets": mean(f.packets for f in flows),
            "mean_flow_duration": mean(f.duration for f in flows),
            "unique_peers": float(len(peers)),
            "unique_dst_ports": float(len(uniq_ports)),
            "dst_port_dispersion": safe_ratio(len(uniq_ports), len(dst_ports)),
            "out_in_byte_ratio": safe_ratio(
                sum(f.bytes for f in out), sum(f.bytes for f in inb), default=float(len(out) > 0)
            ),
            "out_in_flow_ratio": safe_ratio(len(out), len(inb), default=float(len(out) > 0)),
            "dns_query_count": float(len(dns_flows)),
            "unique_domain_count": float(len(uniq_domains)),
            "nxdomain_ratio": safe_ratio(nx, len(dns_flows)),
            "mean_domain_entropy": mean(entropies),
            "max_domain_entropy": max(entropies) if entropies else 0.0,
            "tls_flow_ratio": safe_ratio(len(tls_flows), len(flows)),
            "unique_ja3": float(len(ja3s)),
            "burst_count": float(len(bursts)),
            "mean_burst_gap": mean(burst_gaps),
            "burst_gap_cov": coefficient_of_variation(burst_gaps) if burst_gaps else 0.0,
            "max_inter_burst_periodicity": self._best_periodicity(bursts),
            "mean_burst_bytes": mean(b.byte_count for b in bursts),
            "syn_only_ratio": safe_ratio(syn_only, len(flows)),
        }

        feats = HostWindowFeatures(host=host, window_start=ws, window_end=we, vector=v)
        feats.peers = peers
        feats.top_domains = uniq_domains[:10]
        feats.dst_ports = uniq_ports
        feats.bursts = bursts
        feats.inter_burst_periodicity = v["max_inter_burst_periodicity"]
        return feats

    @staticmethod
    def _best_periodicity(bursts: list[TrafficBurst]) -> float:
        """Highest beaconing regularity across any single host->peer burst chain."""
        by_peer: dict[str, list[float]] = {}
        for b in bursts:
            by_peer.setdefault(b.peer, []).append(b.start_ts)
        best = 0.0
        for starts in by_peer.values():
            if len(starts) >= 3:
                best = max(best, periodicity_score(starts))
        return best
