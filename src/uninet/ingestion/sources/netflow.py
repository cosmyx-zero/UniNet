"""NetFlow / IPFIX / sFlow ingestion via exported CSV.

Collectors (nfdump, softflowd, sflowtool, YAF) all export flow records to CSV;
this source maps a configurable column layout onto :class:`FlowRecord`. The same
class covers the TII-SSRC-23 flow CSVs (see ``datasets/tii_ssrc23.py`` for the
column map used there).
"""
from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from uninet.ingestion.sources.base import FlowSource
from uninet.schemas.flow import FlowRecord, Protocol

# Default column map: nfdump-style CSV (`nfdump -o csv`).
DEFAULT_COLUMNS = {
    "src_ip": "sa",
    "dst_ip": "da",
    "src_port": "sp",
    "dst_port": "dp",
    "protocol": "pr",
    "start_ts": "ts",
    "end_ts": "te",
    "packets": "ipkt",
    "bytes": "ibyt",
    "tcp_flags": "flg",
}

_PROTO_MAP = {
    "tcp": Protocol.TCP, "6": Protocol.TCP,
    "udp": Protocol.UDP, "17": Protocol.UDP,
    "icmp": Protocol.ICMP, "1": Protocol.ICMP,
}


def _to_float_ts(raw: str) -> float:
    raw = (raw or "").strip()
    if not raw:
        return 0.0
    try:
        return float(raw)
    except ValueError:
        # "2023-05-01 12:00:00.000"
        from datetime import datetime

        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt).timestamp()
            except ValueError:
                continue
    return 0.0


class NetFlowCsvSource(FlowSource):
    name = "netflow"

    def __init__(
        self,
        path: str | Path,
        columns: dict[str, str] | None = None,
        source_label: str = "netflow",
        delimiter: str = ",",
    ) -> None:
        self.path = Path(path)
        self.columns = {**DEFAULT_COLUMNS, **(columns or {})}
        self.source_label = source_label
        self.delimiter = delimiter

    def stream(self) -> Iterator[FlowRecord]:
        if not self.path.is_file():
            raise FileNotFoundError(f"NetFlow CSV not found: {self.path}")
        with self.path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh, delimiter=self.delimiter)
            for row in reader:
                rec = self._row_to_record(row)
                if rec is not None:
                    yield rec

    def _get(self, row: dict[str, str], key: str, default: str = "") -> str:
        return (row.get(self.columns.get(key, key), default) or "").strip()

    def _row_to_record(self, row: dict[str, str]) -> FlowRecord | None:
        src_ip = self._get(row, "src_ip")
        dst_ip = self._get(row, "dst_ip")
        if not src_ip or not dst_ip:
            return None
        proto_raw = self._get(row, "protocol").lower()
        start = _to_float_ts(self._get(row, "start_ts"))
        end = _to_float_ts(self._get(row, "end_ts")) or start
        try:
            return FlowRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(self._get(row, "src_port", "0") or 0),
                dst_port=int(self._get(row, "dst_port", "0") or 0),
                protocol=_PROTO_MAP.get(proto_raw, Protocol.OTHER),
                start_ts=start,
                end_ts=end,
                packets=int(float(self._get(row, "packets", "0") or 0)),
                bytes=int(float(self._get(row, "bytes", "0") or 0)),
                tcp_flags=self._get(row, "tcp_flags"),
                dns_qname=self._get(row, "dns_qname") or None,
                tls_sni=self._get(row, "tls_sni") or None,
                ja3=self._get(row, "ja3") or None,
                source=self.source_label,
            )
        except (ValueError, TypeError):
            return None
