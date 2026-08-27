"""End-to-end demo: synthetic (or PCAP) traffic -> alerts, optionally served.

    python -m uninet.demo                 # run pipeline, print alerts
    python -m uninet.demo --json          # emit alerts as JSON
    python -m uninet.demo --serve         # also start dashboard + API
    python -m uninet.demo --pcap capture.pcap
"""
from __future__ import annotations

import argparse
import json
import sys

from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.streaming.worker import PipelineResult, run_pipeline


def _load_source(pcap: str | None, seed: int):
    if pcap:
        from uninet.ingestion.sources.pcap import PcapSource

        return PcapSource(pcap), None
    src = SyntheticSource(seed=seed)
    return src, src.labels


def _print_report(result: PipelineResult, ground_truth: dict | None) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # pragma: no cover
        for a in result.alerts:
            print(f"{a.severity.value.upper():8} {a.threat_type.value:12} {a.src_host:14} "
                  f"conf={a.confidence:.2f}")
        return

    console = Console()
    console.print(
        f"\n[bold]UniNet[/bold]  flows={result.flow_count}  "
        f"windows={result.window_count}  "
        f"graph={result.graph.stats()}  "
        f"alerts={len(result.alerts)}\n"
    )

    table = Table(title="Alerts", show_lines=False, header_style="bold")
    for col in ("severity", "threat", "host", "conf", "rule/anom/graph", "evidence"):
        table.add_column(col)
    sev_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}
    for a in sorted(result.alerts, key=lambda x: -x.confidence):
        sc = a.scores
        table.add_row(
            f"[{sev_color.get(a.severity.value, 'white')}]{a.severity.value.upper()}[/]",
            a.threat_type.value,
            a.src_host,
            f"{a.confidence:.2f}",
            f"{sc.get('rule', 0):.2f}/{sc.get('anomaly', 0):.2f}/{sc.get('graph', 0):.2f}",
            (a.evidence[0].detail[:60] + "…") if a.evidence else "-",
        )
    console.print(table)

    if ground_truth:
        detected = {a.src_host: a.threat_type.value for a in result.alerts}
        gt = Table(title="vs ground truth", header_style="bold")
        for col in ("host", "actual", "detected", "ok"):
            gt.add_column(col)
        for host, actual in sorted(ground_truth.items()):
            got = detected.get(host, "-")
            ok = (
                "[green]OK[/]"
                if (actual == "benign" and got == "-")
                or (actual != "benign" and got in (actual, "unknown"))
                else "[red]MISS[/]"
            )
            gt.add_row(host, actual, got, ok)
        console.print(gt)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="uninet.demo", description=__doc__)
    parser.add_argument("--serve", action="store_true", help="start dashboard + API afterwards")
    parser.add_argument("--no-open", action="store_true", help="do not open a browser when serving")
    parser.add_argument("--pcap", metavar="PATH", help="ingest a PCAP instead of synthetic traffic")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", action="store_true", help="print alerts as JSON only")
    args = parser.parse_args(argv)

    settings = load_settings()
    source, ground_truth = _load_source(args.pcap, args.seed)
    result = run_pipeline(source, settings, detector=Detector.from_settings(settings))

    if args.json:
        json.dump(result.alerts_json(), sys.stdout, indent=2)
        print()
    else:
        _print_report(result, ground_truth)

    if args.serve:
        from uninet.api.app import create_app, serve

        app = create_app(result, settings=settings)
        serve(app, settings, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
