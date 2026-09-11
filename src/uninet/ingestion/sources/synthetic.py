"""Synthetic traffic generator - the zero-infrastructure demo & test fixture.

Produces a labelled mix of benign traffic and attack scenarios so the whole
pipeline (features -> TB-Graph -> detection -> API) is runnable with no PCAP, no
Kafka and no dataset download. Deterministic given ``seed``.

Ground truth is exposed via :attr:`labels` (host -> ThreatType) for evaluation.

Pass ``n_devices`` to scale beyond the canonical 8-host scenario.  Extra hosts
are distributed proportionally: ~70 % benign, ~10 % DDoS, ~5 % each for C2,
DGA, port-scan and data-exfil.  Attack scenarios use lighter per-host flow
counts in scale mode so memory stays manageable.
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

# Extra benign domains for variety at scale
_EXTRA_DOMAINS = [
    "teams.microsoft.com", "zoom.us", "slack.com", "dropbox.com",
    "s3.amazonaws.com", "azure.microsoft.com", "fonts.googleapis.com",
    "analytics.google.com", "cdn.cloudflare.com", "npmjs.com",
]


class SyntheticSource(FlowSource):
    name = "synthetic"

    def __init__(
        self,
        seed: int = 42,
        base_ts: float = 1_700_000_000.0,
        n_devices: int = 8,
    ) -> None:
        self.rng = random.Random(seed)
        self.base_ts = base_ts
        self.n_devices = max(8, n_devices)
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

    def _host_ip(self, idx: int) -> str:
        """Map a flat index (0-based) to a unique 10.x.y.z address."""
        a = (idx // (253 * 253)) & 0xFF
        b = (idx // 253) % 253
        c = idx % 253 + 1
        return f"10.{a + 1}.{b}.{c}"

    def _build(self) -> None:
        # Always generate the canonical 8-host scenario (eval / test fixture).
        self._gen_benign_web("10.0.0.11", ThreatType.BENIGN)
        self._gen_benign_web("10.0.0.12", ThreatType.BENIGN)
        self._gen_benign_dns("10.0.0.13")
        self._gen_ddos("10.0.0.20", target="45.66.71.9")
        self._gen_c2_beacon("10.0.0.31", c2="45.77.100.7")
        self._gen_dga("10.0.0.42")
        self._gen_port_scan("10.0.0.53", target="10.0.0.200")
        self._gen_exfil("10.0.0.64", sink="45.77.200.80")

        if self.n_devices <= 8:
            return

        # Scale mode: distribute extra devices by threat ratio.
        extra = self.n_devices - 8
        n_ddos  = max(1, extra * 10 // 100)
        n_c2    = max(1, extra *  5 // 100)
        n_dga   = max(1, extra *  5 // 100)
        n_scan  = max(1, extra *  5 // 100)
        n_exfil = max(1, extra *  5 // 100)
        n_benign = extra - n_ddos - n_c2 - n_dga - n_scan - n_exfil

        idx = 0  # flat counter into _host_ip space

        all_domains = _BENIGN_DOMAINS + _EXTRA_DOMAINS
        for i in range(n_benign):
            ip = self._host_ip(idx + i)
            if i % 6 == 0:
                self._gen_benign_dns(ip, domains=all_domains)
            else:
                self._gen_benign_web(ip, ThreatType.BENIGN, domains=all_domains)
        idx += n_benign

        for i in range(n_ddos):
            ip = self._host_ip(idx + i)
            target = (
                f"45.{self.rng.randint(80, 220)}."
                f"{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
            )
            # 300 flows is enough to fire the DDoS rule (min=200) without bloating memory.
            self._gen_ddos(ip, target=target, n_flows=300)
        idx += n_ddos

        for i in range(n_c2):
            ip = self._host_ip(idx + i)
            c2 = (
                f"45.{self.rng.randint(80, 220)}."
                f"{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
            )
            self._gen_c2_beacon(ip, c2=c2)
        idx += n_c2

        for i in range(n_dga):
            self._gen_dga(self._host_ip(idx + i))
        idx += n_dga

        for i in range(n_scan):
            ip = self._host_ip(idx + i)
            target = (
                f"10.{self.rng.randint(1, 10)}."
                f"{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
            )
            # 100 distinct ports exceeds the min_unique_dst_ports=50 threshold.
            self._gen_port_scan(ip, target=target, n_ports=100)
        idx += n_scan

        for i in range(n_exfil):
            ip = self._host_ip(idx + i)
            sink = (
                f"45.{self.rng.randint(80, 220)}."
                f"{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
            )
            self._gen_exfil(ip, sink=sink)

    # ---- benign ------------------------------------------------------ #
    def _gen_benign_web(
        self, host: str, label: ThreatType, domains: list[str] | None = None
    ) -> None:
        self.labels[host] = label
        pool = domains or _BENIGN_DOMAINS
        t = self.base_ts
        for _ in range(self.rng.randint(25, 40)):
            t += self.rng.uniform(1.0, 25.0)
            dom = self.rng.choice(pool)
            self._emit(FlowRecord(
                src_ip=host, dst_ip=f"93.184.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}",
                src_port=self.rng.randint(40000, 60000), dst_port=443, protocol=Protocol.TCP,
                start_ts=t, end_ts=t + self.rng.uniform(0.2, 3.0),
                packets=self.rng.randint(8, 60), bytes=self.rng.randint(2_000, 80_000),
                tcp_flags="SPA", tls_sni=dom, ja3="a0e9f5d64349fb13191bc781f81f42e1",
                source="synthetic",
            ))

    def _gen_benign_dns(self, host: str, domains: list[str] | None = None) -> None:
        self.labels[host] = ThreatType.BENIGN
        pool = domains or _BENIGN_DOMAINS
        t = self.base_ts
        for _ in range(self.rng.randint(15, 25)):
            t += self.rng.uniform(2.0, 30.0)
            dom = self.rng.choice(pool)
            self._emit(FlowRecord(
                src_ip=host, dst_ip="10.0.0.1", src_port=self.rng.randint(40000, 60000),
                dst_port=53, protocol=Protocol.UDP, start_ts=t, end_ts=t + 0.05,
                packets=2, bytes=self.rng.randint(120, 320), dns_qname=dom, dns_rcode=0,
                source="synthetic",
            ))

    # ---- DDoS ------------------------------------------------------- #
    def _gen_ddos(self, host: str, target: str, n_flows: int = 4000) -> None:
        self.labels[host] = ThreatType.DDOS
        t = self.base_ts
        for _ in range(n_flows):
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
    def _gen_port_scan(self, host: str, target: str, n_ports: int = 399) -> None:
        self.labels[host] = ThreatType.PORT_SCAN
        t = self.base_ts
        for port in range(1, n_ports + 1):
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
