"""Explainability (Phase 3). Turns fused evidence into human-readable rationale.

Phase 1/2 already attach structured ``Evidence`` to every ``Alert``; this module
will add feature-importance and subgraph-highlight rendering on top.
"""
from uninet.explainability.explainer import explain_alert

__all__ = ["explain_alert"]
