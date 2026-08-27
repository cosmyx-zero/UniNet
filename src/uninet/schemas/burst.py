"""``TrafficBurst`` - a contiguous run of activity between one host and one peer.

Bursts are the atomic unit of the TB-Graph. Splitting a flow timeline into bursts
(by idle gap) and then reasoning about the *relationships between bursts* - order,
direction change, periodicity - is where UniNet's unidirectional-native modelling
lives.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Direction(str, Enum):
    OUTBOUND = "outbound"   # local host -> peer
    INBOUND = "inbound"     # peer -> local host
    UNKNOWN = "unknown"


class TrafficBurst(BaseModel):
    burst_id: str
    host: str                     # the endpoint this burst is anchored on
    peer: str
    direction: Direction = Direction.UNKNOWN

    start_ts: float
    end_ts: float

    flow_count: int = 0
    packet_count: int = 0
    byte_count: int = 0

    protocols: list[str] = Field(default_factory=list)
    dst_ports: list[int] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)

    mean_iat: float = 0.0          # mean inter-flow arrival gap within the burst
    intra_periodicity: float = 0.0 # regularity of flows *inside* the burst [0,1]

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def mean_flow_bytes(self) -> float:
        return self.byte_count / self.flow_count if self.flow_count else 0.0

    @property
    def unique_dst_ports(self) -> int:
        return len(set(self.dst_ports))
