"""Synthetic traffic generator - the zero-infrastructure demo & test fixture.

Produces a labelled mix of benign traffic and attack scenarios so the whole
pipeline (features -> TB-Graph -> detection -> API) is runnable with no PCAP, no
Kafka and no dataset download. Deterministic given ``seed``.

Ground truth is exposed via :attr:`labels` (host -> ThreatType) for evaluation.
"""
from __future__ import annotations

import random
import string
from collections.abc import Iterator

from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.base import FlowSource
from uninet.schemas.flow import FlowRecord, Protocol

_BENIGN_DOMAINS = [
    "update.windows.com", "cdn.jsdelivr.net", "api.github.com", "mail.google.com",
    "pypi.org", "ubuntu.com", "grafana.local", "intranet.corp.local",
]


class SyntheticSource(FlowSource):
    name = "synthetic"

    def __init__(self, seed: int = 42, base_ts: float = 1_700_000_000.0) -> None:
        self.rng = random.Random(seed)
        self.base_ts = base_ts
        self.labels: dict[str, ThreatType] = {}
        self._records: list[FlowRecord] = []
        self._build()

    # ------------------------------------------------------------------ #
    def stream(self) -> Iterator[FlowRecord]:
        yield from sorted(self._records, key=lambda r: r.start_ts)

    # ------------------------------------------------------------------ #
    def _emit(self, rec: FlowRecord) -> None:
        self._records.append(rec)

    def _rand_dga_domain(self) -> str:
        n = self.rng.randint(16, 28)
        label = "".join(self.rng.choice(string.ascii_lowercase) for _ in range(n))
        return f"{label}.{self.rng.choice(['top', 'xyz', 'info', 'ru'])}"

    def _build(self) -> None:
        self._gen_benign_web("10.0.0.11", ThreatType.BENIGN)
        self._gen_benign_web("10.0.0.12", ThreatType.BENIGN)
        self._gen_benign_dns("10.0.0.13")
        self._gen_ddos("10.0.0.20", target="45.66.71.9")
        self._gen_c2_beacon("10.0.0.31", c2="45.77.100.7")
        self._gen_dga("10.0.0.42")
        self._gen_port_scan("10.0.0.53", target="10.0.0.200")
        self._gen_exfil("10.0.0.64", sink="45.77.200.80")

    # ---- benign ------------------------------------------------------ #
    def _gen_benign_web(self, host: str, label: ThreatType) -> None:
        self.labels[host] = label
        t = self.base_ts
        for _ in range(self.rng.randint(25, 40)):
            t += self.rng.uniform(1.0, 25.0)
            dom = self.rng.choice(_BENIGN_DOMAINS)
            self._emit(FlowRecord(
                src_ip=host, dst_ip=f"93.184.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}",
                src_port=self.rng.randint(40000, 60000), dst_port=443, protocol=Protocol.TCP,
                start_ts=t, end_ts=t + self.rng.uniform(0.2, 3.0),
                packets=self.rng.randint(8, 60), bytes=self.rng.randint(2_000, 80_000),
                tcp_flags="SPA", tls_sni=dom, ja3="a0e9f5d64349fb13191bc781f81f42e1",
                source="synthetic",
            ))

    def _gen_benign_dns(self, host: str) -> None:
        self.labels[host] = ThreatType.BENIGN
        t = self.base_ts
        for _ in range(self.rng.randint(15, 25)):
            t += self.rng.uniform(2.0, 30.0)
            dom = self.rng.choice(_BENIGN_DOMAINS)
            self._emit(FlowRecord(
                src_ip=host, dst_ip="10.0.0.1", src_port=self.rng.randint(40000, 60000),
                dst_port=53, protocol=Protocol.UDP, start_ts=t, end_ts=t + 0.05,
                packets=2, bytes=self.rng.randint(120, 320), dns_qname=dom, dns_rcode=0,
                source="synthetic",
            ))

    # ---- DDoS ------------------------------------------------------- #
    def _gen_ddos(self, host: str, target: str) -> None:
        self.labels[host] = ThreatType.DDOS
        t = self.base_ts
        for _ in range(4000):
            t += self.rng.uniform(0.001, 0.006)
            self._emit(FlowRecord(
                src_ip=host, dst_ip=target, src_port=self.rng.randint(1024, 65535),
                dst_port=80, protocol=Protocol.TCP, start_ts=t, end_ts=t + 0.002,
                packets=self.rng.randint(1, 3), bytes=self.rng.randint(40, 120),
                tcp_flags="S", source="synthetic",
            ))

    # ---- C2 beacon ------------------------------------------------- #
    def _gen_c2_beacon(self, host: str, c2: str) -> None:
        self.labels[host] = ThreatType.C2_BEACON
        t = self.base_ts
        interval = 30.0
        for _ in range(20):
            jitter = self.rng.uniform(-1.5, 1.5)
            t += interval + jitter
            self._emit(FlowRecord(
                src_ip=host, dst_ip=c2, src_port=self.rng.randint(40000, 60000),
                dst_port=443, protocol=Protocol.TCP, start_ts=t, end_ts=t + 0.3,
                packets=self.rng.randint(6, 12), bytes=self.rng.randint(400, 1500),
                tcp_flags="SPA", tls_sni="cdn-status-check.net",
                ja3="e7d705a3286e19ea42f587b344ee6865",
                source="synthetic",
            ))

    # ---- DGA ------------------------------------------------------- #
    def _gen_dga(self, host: str) -> None:
        self.labels[host] = ThreatType.DGA
        t = self.base_ts
        for _ in range(40):
            t += self.rng.uniform(0.5, 4.0)
            self._emit(FlowRecord(
                src_ip=host, dst_ip="10.0.0.1", src_port=self.rng.randint(40000, 60000),
                dst_port=53, protocol=Protocol.UDP, start_ts=t, end_ts=t + 0.05,
                packets=2, bytes=self.rng.randint(120, 300),
                dns_qname=self._rand_dga_domain(),
                dns_rcode=self.rng.choice([0, 3, 3, 3]),  # mostly NXDOMAIN
                source="synthetic",
            ))

    # ---- port scan ----------------------------------------------- #
    def _gen_port_scan(self, host: str, target: str) -> None:
        self.labels[host] = ThreatType.PORT_SCAN
        t = self.base_ts
        for port in range(1, 400):
            t += self.rng.uniform(0.005, 0.03)
            self._emit(FlowRecord(
                src_ip=host, dst_ip=target, src_port=self.rng.randint(40000, 60000),
                dst_port=port, protocol=Protocol.TCP, start_ts=t, end_ts=t + 0.001,
                packets=1, bytes=44, tcp_flags="S", source="synthetic",
            ))

    # ---- data exfiltration ------------------------------------- #
    def _gen_exfil(self, host: str, sink: str) -> None:
        self.labels[host] = ThreatType.DATA_EXFIL
        t = self.base_ts
        for _ in range(40):
            t += self.rng.uniform(1.0, 5.0)
            self._emit(FlowRecord(
                src_ip=host, dst_ip=sink, src_port=self.rng.randint(40000, 60000),
                dst_port=443, protocol=Protocol.TCP, start_ts=t, end_ts=t + self.rng.uniform(2.0, 8.0),
                packets=self.rng.randint(800, 2000), bytes=self.rng.randint(1_800_000, 3_500_000),
                tcp_flags="SPA", tls_sni="backup-sync.example", source="synthetic",
            ))
        # small inbound acks so the out:in ratio is realistic, not infinite
        for _ in range(20):
            t += self.rng.uniform(1.0, 5.0)
            self._emit(FlowRecord(
                src_ip=sink, dst_ip=host, src_port=443, dst_port=self.rng.randint(40000, 60000),
                protocol=Protocol.TCP, start_ts=t, end_ts=t + 0.5,
                packets=self.rng.randint(5, 15), bytes=self.rng.randint(400, 1200),
                tcp_flags="A", source="synthetic",
            ))
