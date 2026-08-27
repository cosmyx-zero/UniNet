"""Behavioural fingerprinting.

Two layers:
  * TLS/QUIC fingerprints (JA3 / JA3S / JA4) come straight off the wire metadata
    and are carried on ``FlowRecord``; :func:`ja3_set` just aggregates them.
  * A *behavioural* fingerprint is a stable hash of a host's coarse activity
    profile (ports it talks to, protocol mix, periodicity band). Two hosts with
    the same fingerprint are behaving alike - useful for spotting botnet cohorts.
"""
from __future__ import annotations

import hashlib

from uninet.features.extractor import HostWindowFeatures
from uninet.schemas.flow import FlowRecord


def ja3_set(flows: list[FlowRecord]) -> set[str]:
    return {f.ja3 for f in flows if f.ja3} | {f.ja4 for f in flows if f.ja4}


def _band(value: float, edges: tuple[float, ...]) -> int:
    return sum(1 for e in edges if value >= e)


def behavioural_fingerprint(feats: HostWindowFeatures) -> str:
    """Deterministic short hex digest of a host's behaviour profile."""
    v = feats.vector
    profile = (
        tuple(sorted(feats.dst_ports))[:12],
        _band(v.get("flows_per_second", 0.0), (1, 10, 100, 1000)),
        _band(v.get("out_in_byte_ratio", 0.0), (2, 8, 32)),
        _band(v.get("mean_domain_entropy", 0.0), (2.5, 3.2, 3.8)),
        _band(v.get("max_inter_burst_periodicity", 0.0), (0.5, 0.75, 0.9)),
        _band(v.get("unique_dst_ports", 0.0), (5, 20, 50, 200)),
    )
    digest = hashlib.sha1(repr(profile).encode("utf-8")).hexdigest()
    return digest[:16]
