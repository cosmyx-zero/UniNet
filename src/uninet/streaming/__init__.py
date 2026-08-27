"""Streaming transport. Default is a zero-dependency in-process bus; Kafka is opt-in."""
from uninet.streaming.bus import InProcBus, MessageBus, make_bus

__all__ = ["InProcBus", "MessageBus", "make_bus"]
