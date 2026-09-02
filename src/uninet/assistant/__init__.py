"""Read-only analyst assistant (Phase 4).

HARD CONSTRAINT - enforced by tests/test_assistant_readonly.py:
this package must never import networking, subprocess, or packet-crafting modules.
It can READ alerts, evidence, the TB-Graph and explanations; it can do NOTHING
that touches the network, a shell, a firewall, or packet injection.

<<<<<<< HEAD
The assistant is templated and offline - it answers from the context bundle only,
with no LLM call, so the guarantee holds by construction.
"""
from uninet.assistant.assistant import ask, classify
from uninet.assistant.context import AssistantContext, build_context

__all__ = ["AssistantContext", "ask", "build_context", "classify"]
=======
Phase 1/2 ship only the read-only context builder; the natural-language layer
lands in Phase 4.
"""
from uninet.assistant.context import AssistantContext, build_context

__all__ = ["AssistantContext", "build_context"]
>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
