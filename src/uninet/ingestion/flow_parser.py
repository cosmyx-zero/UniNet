"""Normalization helpers applied to every ``FlowRecord`` regardless of source.

Keeps the notion of "which endpoint is the monitored/local host" in one place so
burst building and features can speak in host/peer terms.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator

from uninet.schemas.burst import Direction
from uninet.schemas.flow import FlowRecord


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def local_host_of(rec: FlowRecord) -> str:
    """Pick the endpoint we anchor analysis on: prefer the private/internal side."""
    if is_private(rec.src_ip) and not is_private(rec.dst_ip):
        return rec.src_ip
    if is_private(rec.dst_ip) and not is_private(rec.src_ip):
        return rec.dst_ip
    return rec.src_ip  # both private (or both public): src is the actor


def direction_of(rec: FlowRecord, host: str) -> Direction:
    if rec.src_ip == host:
        return Direction.OUTBOUND
    if rec.dst_ip == host:
        return Direction.INBOUND
    return Direction.UNKNOWN


def peer_of(rec: FlowRecord, host: str) -> str:
    return rec.dst_ip if rec.src_ip == host else rec.src_ip


def sort_by_time(records: Iterable[FlowRecord]) -> list[FlowRecord]:
    return sorted(records, key=lambda r: (r.start_ts, r.end_ts))


def clip_to_window(
    records: Iterable[FlowRecord], start: float, end: float
) -> Iterator[FlowRecord]:
    for r in records:
        if r.start_ts >= start and r.start_ts < end:
            yield r
