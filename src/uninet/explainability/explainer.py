"""Render an :class:`Alert` into an analyst-facing explanation.

Phase 1/2 scope: reformat the evidence the detector already produced (rule hits,
anomaly score, TB-Graph structure) into an ordered, weighted "why" list plus the
graph anchors to highlight. Phase 3 extends this with per-feature importance.
"""
from __future__ import annotations

from uninet.schemas.alert import Alert


def explain_alert(alert: Alert) -> dict:
    ordered = sorted(alert.evidence, key=lambda e: -e.score)
    return {
        "alert_id": alert.alert_id,
        "verdict": f"{alert.threat_type.value} ({alert.severity.value})",
        "confidence": alert.confidence,
        "fused_from": alert.scores,
        "why": [
            {
                "signal": e.kind.value,
                "name": e.name,
                "weight": round(e.score, 3),
                "detail": e.detail,
            }
            for e in ordered
        ],
        "graph_anchors": alert.graph_node_ids,
        "window": [alert.window_start, alert.window_end],
    }
