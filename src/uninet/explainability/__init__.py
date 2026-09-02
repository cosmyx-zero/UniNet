"""Explainability (Phase 3). Turns fused evidence into human-readable rationale.

<<<<<<< HEAD
Every ``Alert`` already carries structured ``Evidence``; this module renders it as
an ordered "why", concrete key factors, a burst timeline, graph anchors and a
short narrative - all derived from the alert, no model re-run.
"""
from uninet.explainability.explainer import explain_alert, feature_importance

__all__ = ["explain_alert", "feature_importance"]
=======
Phase 1/2 already attach structured ``Evidence`` to every ``Alert``; this module
will add feature-importance and subgraph-highlight rendering on top.
"""
from uninet.explainability.explainer import explain_alert

__all__ = ["explain_alert"]
>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
