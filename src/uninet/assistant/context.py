"""Assemble a READ-ONLY evidence bundle for the analyst assistant.

Everything here is a pure read over objects the pipeline already produced. No I/O,
no network, no mutation.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from uninet.explainability.explainer import explain_alert
from uninet.schemas.alert import Alert
from uninet.schemas.graph import TBGraphView


@dataclass
class AssistantContext:
    alert: dict
    explanation: dict
    subgraph: dict = field(default_factory=dict)

    def as_prompt_context(self) -> str:
<<<<<<< HEAD
        """Flat text block the assistant (or a future LLM layer) is grounded on."""
=======
        """Flat text block a Phase 4 LLM layer can be grounded on (read-only)."""
>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
        e = self.explanation
        lines = [
            f"ALERT {self.alert['alert_id']}: {e['verdict']} conf={e['confidence']}",
            f"host={self.alert['src_host']} peers={self.alert.get('peers', [])}",
            "evidence:",
            *[f"  - [{w['signal']}] {w['detail']} (w={w['weight']})" for w in e["why"]],
            f"graph_anchors={e['graph_anchors']}",
        ]
        return "\n".join(lines)


def build_context(alert: Alert, subgraph_view: TBGraphView | None = None) -> AssistantContext:
    return AssistantContext(
        alert=alert.model_dump(mode="json"),
        explanation=explain_alert(alert),
        subgraph=subgraph_view.model_dump(mode="json") if subgraph_view else {},
    )
