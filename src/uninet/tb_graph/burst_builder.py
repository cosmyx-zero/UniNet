"""Flows -> Traffic Bursts.

For each (host, peer) pair the flow timeline is split wherever the inter-flow gap
exceeds ``gap_seconds``. Each resulting burst carries volume, direction, port and
domain summaries plus an intra-burst regularity score.
"""
from __future__ import annotations

from uninet.ingestion.flow_parser import direction_of, local_host_of, peer_of, sort_by_time
from uninet.schemas.burst import Direction, TrafficBurst
from uninet.schemas.flow import FlowRecord
from uninet.utils import periodicity_score


class BurstBuilder:
    def __init__(self, gap_seconds: float = 2.0) -> None:
        self.gap_seconds = float(gap_seconds)

    def build(self, flows: list[FlowRecord], host: str | None = None) -> list[TrafficBurst]:
        if not flows:
            return []

        anchor = host or local_host_of(flows[0])
        by_peer: dict[str, list[FlowRecord]] = {}
        for f in flows:
            by_peer.setdefault(peer_of(f, anchor), []).append(f)

        bursts: list[TrafficBurst] = []
        for peer, peer_flows in by_peer.items():
            bursts.extend(self._split_peer(anchor, peer, sort_by_time(peer_flows)))
        return sort_by_time_bursts(bursts)

    def _split_peer(
        self, host: str, peer: str, flows: list[FlowRecord]
    ) -> list[TrafficBurst]:
        groups: list[list[FlowRecord]] = [[]]
        last_end: float | None = None
        for f in flows:
            if last_end is not None and (f.start_ts - last_end) > self.gap_seconds:
                groups.append([])
            groups[-1].append(f)
            last_end = max(last_end or f.end_ts, f.end_ts)

        out: list[TrafficBurst] = []
        for i, grp in enumerate(groups):
            if not grp:
                continue
            out.append(self._make_burst(host, peer, grp, i))
        return out

    @staticmethod
    def _make_burst(
        host: str, peer: str, flows: list[FlowRecord], idx: int
    ) -> TrafficBurst:
        dirs = {direction_of(f, host) for f in flows}
        if dirs == {Direction.OUTBOUND}:
            direction = Direction.OUTBOUND
        elif dirs == {Direction.INBOUND}:
            direction = Direction.INBOUND
        else:
            direction = Direction.UNKNOWN

        starts = sorted(f.start_ts for f in flows)
        iats = [b - a for a, b in zip(starts, starts[1:])]
        mean_iat = sum(iats) / len(iats) if iats else 0.0

        return TrafficBurst(
            burst_id=f"{host}->{peer}#{idx}@{int(starts[0])}",
            host=host,
            peer=peer,
            direction=direction,
            start_ts=starts[0],
            end_ts=max(f.end_ts for f in flows),
            flow_count=len(flows),
            packet_count=sum(f.packets for f in flows),
            byte_count=sum(f.bytes for f in flows),
            protocols=sorted({f.protocol.value for f in flows}),
            dst_ports=sorted({f.dst_port for f in flows if f.dst_port}),
            domains=sorted({f.dns_qname for f in flows if f.dns_qname}),
            mean_iat=mean_iat,
            intra_periodicity=periodicity_score(starts) if len(starts) >= 3 else 0.0,
        )


def sort_time_key(b: TrafficBurst) -> tuple[float, float]:
    return (b.start_ts, b.end_ts)


def sort_by_time_bursts(bursts: list[TrafficBurst]) -> list[TrafficBurst]:
    return sorted(bursts, key=sort_time_key)
