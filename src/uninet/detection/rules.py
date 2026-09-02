"""Statistical / rule-based detectors - the interpretable half of the hybrid engine.

Each rule inspects one :class:`HostWindowFeatures` and, if it fires, returns a
:class:`RuleHit` carrying a candidate :class:`ThreatType`, a confidence in [0, 1]
and a human-readable :class:`Evidence` record. Thresholds come from
``config/threat_rules.yaml``.
"""
from __future__ import annotations

from dataclasses import dataclass

from uninet.config import load_threat_rules
from uninet.detection.threat_types import ThreatType
from uninet.features.extractor import HostWindowFeatures
from uninet.schemas.alert import Evidence, EvidenceKind
from uninet.utils import clamp01, ramp


@dataclass
class RuleHit:
    threat_type: ThreatType
    confidence: float
    evidence: Evidence


class RuleEngine:
    def __init__(self, config: dict | None = None) -> None:
        self.cfg = config or load_threat_rules()

    def run(self, feats: HostWindowFeatures) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in (
            self._ddos, self._c2_beacon, self._dga, self._port_scan, self._data_exfil
        ):
            hit = rule(feats)
            if hit is not None and hit.confidence > 0:
                hits.append(hit)
        return hits

    # ------------------------------------------------------------------ #
    def _ddos(self, f: HostWindowFeatures) -> RuleHit | None:
        c = self.cfg.get("ddos", {})
        v = f.vector
        flows = v.get("flow_count", 0.0)
        pps = v.get("packets_per_second", 0.0)
        if flows < c.get("min_flows_per_window", 200):
            return None
        if pps < c.get("min_packets_per_second", 500):
            return None
        small = v.get("mean_flow_bytes", 1e9) <= c.get("max_mean_flow_bytes", 400)
        conf = clamp01(
            0.5 * ramp(flows, c.get("min_flows_per_window", 200),
                       2 * c.get("min_flows_per_window", 200))
            + 0.3 * ramp(pps, c.get("min_packets_per_second", 500),
                         2 * c.get("min_packets_per_second", 500))
            + (0.2 if small else 0.0)
        )
        return RuleHit(
            ThreatType.DDOS, conf,
            Evidence(
                kind=EvidenceKind.RULE, name="volumetric_flood",
                detail=(
                    f"{int(flows)} flows / {pps:.0f} pkt/s toward {len(f.peers)} peer(s), "
                    f"mean {v.get('mean_flow_bytes', 0):.0f} B/flow"
                ),
                score=conf,
                data={"flow_count": flows, "packets_per_second": pps},
            ),
        )

    def _c2_beacon(self, f: HostWindowFeatures) -> RuleHit | None:
        c = self.cfg.get("c2_beacon", {})
        v = f.vector
        if v.get("burst_count", 0.0) < c.get("min_bursts", 4):
            return None
        # DNS-dominated regularity is DGA / tunnelling territory, not an HTTPS beacon.
        if v.get("dns_query_count", 0.0) >= 0.8 * max(v.get("flow_count", 1.0), 1.0):
            return None
        periodicity = v.get("max_inter_burst_periodicity", 0.0)
        cov_ok = v.get("burst_gap_cov", 1.0) <= c.get("max_interval_cov", 0.25)
        small = v.get("mean_burst_bytes", 1e9) <= c.get("max_burst_bytes", 5000)
        if periodicity < 0.6 and not cov_ok:
            return None
        conf = clamp01(
            0.6 * periodicity + (0.25 if cov_ok else 0.0) + (0.15 if small else 0.0)
        )
        if conf < c.get("min_confidence", 0.6):
            return None
        peer = f.bursts[0].peer if f.bursts else "?"
        return RuleHit(
            ThreatType.C2_BEACON, conf,
            Evidence(
                kind=EvidenceKind.RULE, name="beacon_periodicity",
                detail=(
                    f"{int(v.get('burst_count', 0))} regular check-ins to {peer} "
                    f"(periodicity {periodicity:.2f}, gap CoV {v.get('burst_gap_cov', 0):.2f})"
                ),
                score=conf,
                data={"periodicity": periodicity, "gap_cov": v.get("burst_gap_cov", 0.0)},
            ),
        )

    def _dga(self, f: HostWindowFeatures) -> RuleHit | None:
        c = self.cfg.get("dga", {})
        v = f.vector
        uniq = v.get("unique_domain_count", 0.0)
        ent = v.get("mean_domain_entropy", 0.0)
        nx = v.get("nxdomain_ratio", 0.0)
        if uniq < c.get("min_unique_domains", 15):
            return None
        if ent < c.get("min_mean_label_entropy", 3.4):
            return None
        conf = clamp01(
            0.4 * ramp(ent, 3.0, 4.3)
            + 0.35 * ramp(nx, c.get("min_nxdomain_ratio", 0.3), 0.85)
            + 0.25 * ramp(uniq, c.get("min_unique_domains", 15), 60)
        )
        if conf < c.get("min_confidence", 0.6):
            return None
        return RuleHit(
            ThreatType.DGA, conf,
            Evidence(
                kind=EvidenceKind.RULE, name="dga_domain_entropy",
                detail=(
                    f"{int(uniq)} unique domains, mean label entropy {ent:.2f} bits/char, "
                    f"{nx * 100:.0f}% NXDOMAIN"
                ),
                score=conf,
                data={"unique_domains": uniq, "mean_entropy": ent, "nxdomain_ratio": nx},
            ),
        )

    def _port_scan(self, f: HostWindowFeatures) -> RuleHit | None:
        c = self.cfg.get("port_scan", {})
        v = f.vector
        ports = v.get("unique_dst_ports", 0.0)
        if ports < c.get("min_unique_dst_ports", 50):
            return None
        if v.get("mean_flow_packets", 1e9) > c.get("max_mean_flow_packets", 3):
            return None
        if v.get("mean_flow_bytes", 1e9) > c.get("max_mean_flow_bytes", 300):
            return None
        conf = clamp01(
            0.55 * ramp(ports, c.get("min_unique_dst_ports", 50), 400)
            + 0.45 * v.get("syn_only_ratio", 0.0)
        )
        return RuleHit(
            ThreatType.PORT_SCAN, conf,
            Evidence(
                kind=EvidenceKind.RULE, name="port_sweep",
                detail=(
                    f"{int(ports)} distinct destination ports, "
                    f"{v.get('syn_only_ratio', 0) * 100:.0f}% SYN-only, "
                    f"{v.get('mean_flow_bytes', 0):.0f} B/flow"
                ),
                score=conf,
                data={"unique_dst_ports": ports, "syn_only_ratio": v.get("syn_only_ratio", 0.0)},
            ),
        )

    def _data_exfil(self, f: HostWindowFeatures) -> RuleHit | None:
        c = self.cfg.get("data_exfil", {})
        v = f.vector
        out_bytes = v.get("byte_count", 0.0) * (
            v.get("out_in_byte_ratio", 0.0) / (1.0 + v.get("out_in_byte_ratio", 0.0))
        )
        ratio = v.get("out_in_byte_ratio", 0.0)
        if out_bytes < c.get("min_outbound_bytes", 52428800):
            return None
        if ratio < c.get("min_out_in_ratio", 8.0):
            return None
        if v.get("unique_peers", 1e9) > c.get("max_peers", 3):
            return None
        conf = clamp01(
            0.5 * ramp(out_bytes, c.get("min_outbound_bytes", 52428800),
                       4 * c.get("min_outbound_bytes", 52428800))
            + 0.5 * ramp(ratio, c.get("min_out_in_ratio", 8.0), 40.0)
        )
        return RuleHit(
            ThreatType.DATA_EXFIL, conf,
            Evidence(
                kind=EvidenceKind.RULE, name="egress_volume",
                detail=(
                    f"~{out_bytes / 1e6:.1f} MB outbound to {int(v.get('unique_peers', 0))} peer(s), "
                    f"out:in byte ratio {ratio:.1f}"
                ),
                score=conf,
                data={"outbound_bytes": out_bytes, "out_in_ratio": ratio},
            ),
        )
