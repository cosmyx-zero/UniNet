"""``FlowRecord`` - the single normalized shape every ingestion source converges to.

PCAP, NetFlow v5/v9, IPFIX and sFlow all differ in wire format; downstream code
(features, TB-Graph, detection) only ever sees a ``FlowRecord``. The record is
*unidirectional by construction*: one row = traffic observed in one direction.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, field_validator


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class FlowRecord(BaseModel):
    """One observed unidirectional flow (or flow-slice) between two endpoints."""

    # --- identity --------------------------------------------------------
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: Protocol = Protocol.OTHER

    # --- timing (epoch seconds) ---------------------------------------
    start_ts: float
    end_ts: float

    # --- volume (observed direction only) ---------------------------------
    packets: int = 0
    bytes: int = 0

    # --- optional metadata (never payload) -----------------------------
    tcp_flags: str = ""            # e.g. "S", "SA", "PA" - union over the flow
    dns_qname: str | None = None   # queried name, if this flow carried a DNS query
    dns_rcode: int | None = None   # 0 = NOERROR, 3 = NXDOMAIN
    tls_sni: str | None = None
    ja3: str | None = None         # client TLS fingerprint (md5 hex)
    ja3s: str | None = None        # server TLS fingerprint
    ja4: str | None = None         # JA4 / JA4S fingerprint string

    # --- provenance --------------------------------------------------------
    source: str = "unknown"        # "pcap", "netflow", "synthetic", ...
    observed_by: str = "sensor-0"  # which one-way tap produced this

    model_config = {"extra": "ignore"}

    @field_validator("end_ts")
    @classmethod
    def _end_after_start(cls, v: float, info):
        start = info.data.get("start_ts")
        if start is not None and v < start:
            return start
        return v

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def bits_per_second(self) -> float:
        d = self.duration
        return (self.bytes * 8) / d if d > 0 else float(self.bytes * 8)

    @property
    def is_dns(self) -> bool:
        return self.dns_qname is not None or self.dst_port == 53 or self.src_port == 53

    @property
    def is_tls(self) -> bool:
        return bool(self.tls_sni or self.ja3) or self.dst_port in (443, 853)
