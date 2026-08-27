"""Replay a PCAP (or synthetic traffic) onto the message bus at a controlled rate.

    python scripts/replay_pcap.py --pcap capture.pcap --rate 500
    python scripts/replay_pcap.py --synthetic --rate 1000

Simulates a live one-way feed for demos. With --run it also drains the bus
through the detection pipeline and prints the resulting alerts.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uninet.config import load_settings
from uninet.streaming.bus import InProcBus, make_bus


def _source(args):
    if args.synthetic or not args.pcap:
        from uninet.ingestion.sources.synthetic import SyntheticSource

        return SyntheticSource()
    from uninet.ingestion.sources.pcap import PcapSource

    return PcapSource(args.pcap)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pcap", metavar="PATH")
    p.add_argument("--synthetic", action="store_true")
    p.add_argument("--rate", type=float, default=0.0, help="flows/sec (0 = as fast as possible)")
    p.add_argument("--run", action="store_true", help="also run detection and print alerts")
    args = p.parse_args(argv)

    settings = load_settings()
    bus = InProcBus() if settings.bus == "inproc" else make_bus("kafka", settings.kafka_brokers)
    topic = settings.kafka_topic

    delay = 1.0 / args.rate if args.rate > 0 else 0.0
    n = 0
    for rec in _source(args).stream():
        bus.publish(topic, rec)
        n += 1
        if delay:
            time.sleep(delay)
    if isinstance(bus, InProcBus):
        bus.seal(topic)
    print(f"replayed {n} flows onto '{topic}'")

    if args.run:
        from uninet.detection.detector import Detector
        from uninet.ingestion.sources.base import FlowSource
        from uninet.streaming.worker import run_pipeline

        drained = list(bus.consume(topic))

        class _Drained(FlowSource):
            name = "drained"

            def stream(self):
                yield from drained

        result = run_pipeline(_Drained(), settings, detector=Detector.from_settings(settings),
                              use_bus=False)
        print(f"\n{len(result.alerts)} alert(s):")
        for a in sorted(result.alerts, key=lambda x: -x.confidence):
            print(f"  {a.severity.value.upper():8} {a.threat_type.value:12} {a.src_host:16} "
                  f"conf={a.confidence:.2f}")
    bus.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
