<<<<<<< HEAD
"""Streaming transport + pipeline. In-process bus by default; Kafka is opt-in."""
from uninet.streaming.bus import InProcBus, MessageBus, make_bus
from uninet.streaming.service import LiveService, run_sharded
from uninet.streaming.worker import PipelineResult, merge_results, run_pipeline

__all__ = [
    "InProcBus",
    "LiveService",
    "MessageBus",
    "PipelineResult",
    "make_bus",
    "merge_results",
    "run_pipeline",
    "run_sharded",
]
=======
"""Streaming transport. Default is a zero-dependency in-process bus; Kafka is opt-in."""
from uninet.streaming.bus import InProcBus, MessageBus, make_bus

__all__ = ["InProcBus", "MessageBus", "make_bus"]
>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
