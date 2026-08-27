"""Read-only analyst assistant (Phase 4).

HARD CONSTRAINT - enforced by tests/test_assistant_readonly.py:
this package must never import networking, subprocess, or packet-crafting modules.
It can READ alerts, evidence, the TB-Graph and explanations; it can do NOTHING
that touches the network, a shell, a firewall, or packet injection.

Phase 1/2 ship only the read-only context builder; the natural-language layer
lands in Phase 4.
"""
from uninet.assistant.context import AssistantContext, build_context

__all__ = ["AssistantContext", "build_context"]
