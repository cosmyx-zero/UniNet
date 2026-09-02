"""Offline PCAP ingestion (read-only).

Requires the ``pcap`` extra:  ``pip install -e ".[pcap]"`` (scapy). Packets are
aggregated into unidirectional flows keyed by (src, dst, sport, dport, proto).
Live capture is intentionally *not* implemented here - in a real deployment the
one-way tap / data-diode feeds a PCAP or NetFlow export; the sensor host never
originates traffic.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from uninet.ingestion.sources.base import FlowSource
from uninet.schemas.flow import FlowRecord, Protocol


class PcapSource(FlowSource):
    name = "pcap"

    def __init__(self, path: str | Path, source_label: str = "pcap") -> None:
        self.path = Path(path)
        self.source_label = source_label

    def stream(self) -> Iterator[FlowRecord]:
        try:
            from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapReader  # type: ignore
        except ImportError as exc:  # pragma: no cover - env dependent
            raise RuntimeError(
                "PCAP ingestion needs scapy. Install with: pip install -e \".[pcap]\""
            ) from exc

        if not self.path.is_file():
            raise FileNotFoundError(f"PCAP not found: {self.path}")

        agg: dict[tuple, dict] = defaultdict(
            lambda: {
                "packets": 0, "bytes": 0, "start": None, "end": None,
                "flags": set(), "qname": None, "rcode": None, "sni": None,
            }
        )

        with PcapReader(str(self.path)) as reader:
            for pkt in reader:
                if IP not in pkt:
                    continue
                ip = pkt[IP]
                proto, sport, dport = Protocol.OTHER, 0, 0
                if TCP in pkt:
                    proto, sport, dport = Protocol.TCP, int(pkt[TCP].sport), int(pkt[TCP].dport)
                elif UDP in pkt:
                    proto, sport, dport = Protocol.UDP, int(pkt[UDP].sport), int(pkt[UDP].dport)
                elif ip.proto == 1:
                    proto = Protocol.ICMP

                key = (ip.src, ip.dst, sport, dport, proto.value)
                slot = agg[key]
                ts = float(pkt.time)
                slot["packets"] += 1
                slot["bytes"] += len(pkt)
                slot["start"] = ts if slot["start"] is None else min(slot["start"], ts)
                slot["end"] = ts if slot["end"] is None else max(slot["end"], ts)
                if TCP in pkt:
                    slot["flags"].add(str(pkt[TCP].flags))
                if DNS in pkt and pkt[DNS].qd is not None:
                    try:
                        slot["qname"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                        slot["rcode"] = int(pkt[DNS].rcode)
                    except Exception:  # pragma: no cover - malformed packet
                        pass

        for (src, dst, sport, dport, proto_v), slot in agg.items():
            start = slot["start"] or 0.0
            yield FlowRecord(
                src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                protocol=Protocol(proto_v),
                start_ts=start, end_ts=slot["end"] or start,
                packets=slot["packets"], bytes=slot["bytes"],
                tcp_flags="".join(sorted(slot["flags"]))[:8],
                dns_qname=slot["qname"], dns_rcode=slot["rcode"],
                tls_sni=slot["sni"],
                source=self.source_label,
            )
