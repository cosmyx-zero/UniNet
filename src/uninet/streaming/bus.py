"""Message bus abstraction.

The pipeline is streaming-shaped from Phase 1: sources publish ``FlowRecord``s to a
topic, workers consume them. ``InProcBus`` (default) needs nothing. ``KafkaBus``
models the "simulated one-way topic" from the proposal - the consumer group only
ever reads; there is no producer path back toward the monitored network.
"""
from __future__ import annotations

import abc
import json
import queue
from collections.abc import Iterator

from uninet.schemas.flow import FlowRecord


class MessageBus(abc.ABC):
    @abc.abstractmethod
    def publish(self, topic: str, record: FlowRecord) -> None: ...

    @abc.abstractmethod
    def consume(self, topic: str, timeout: float | None = None) -> Iterator[FlowRecord]:
        """Yield records until the stream is exhausted / times out."""

    def close(self) -> None:  # pragma: no cover - trivial
        pass


class InProcBus(MessageBus):
    """Single-process queue. Publish everything, then consume drains it."""

    _SENTINEL = object()

    def __init__(self) -> None:
        self._topics: dict[str, queue.Queue] = {}

    def _q(self, topic: str) -> queue.Queue:
        return self._topics.setdefault(topic, queue.Queue())

    def publish(self, topic: str, record: FlowRecord) -> None:
        self._q(topic).put(record)

    def seal(self, topic: str) -> None:
        """Mark the topic complete so a bounded ``consume`` can stop."""
        self._q(topic).put(self._SENTINEL)

    def consume(self, topic: str, timeout: float | None = 0.0) -> Iterator[FlowRecord]:
        q = self._q(topic)
        while True:
            try:
                item = q.get(block=timeout is not None and timeout > 0, timeout=timeout or None)
            except queue.Empty:
                return
            if item is self._SENTINEL:
                return
            yield item


class KafkaBus(MessageBus):  # pragma: no cover - requires a broker
    """Kafka-backed one-way topic. Needs the ``stream`` extra (kafka-python)."""

    def __init__(self, brokers: str, group_id: str = "uninet-detectors") -> None:
        try:
            from kafka import KafkaConsumer, KafkaProducer  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                'Kafka bus needs kafka-python. Install with: pip install -e ".[stream]"'
            ) from exc
        self._KafkaConsumer = KafkaConsumer
        self._brokers = brokers.split(",")
        self._group_id = group_id
        self._producer = KafkaProducer(
            bootstrap_servers=self._brokers,
            value_serializer=lambda r: r.model_dump_json().encode("utf-8"),
        )

    def publish(self, topic: str, record: FlowRecord) -> None:
        self._producer.send(topic, record)

    def consume(self, topic: str, timeout: float | None = 5.0) -> Iterator[FlowRecord]:
        consumer = self._KafkaConsumer(
            topic,
            bootstrap_servers=self._brokers,
            group_id=self._group_id,
            auto_offset_reset="earliest",
            consumer_timeout_ms=int((timeout or 5.0) * 1000),
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )
        for msg in consumer:
            yield FlowRecord(**msg.value)
        consumer.close()

    def close(self) -> None:
        self._producer.flush()
        self._producer.close()


def make_bus(kind: str, brokers: str = "localhost:9092") -> MessageBus:
    if kind == "kafka":
        return KafkaBus(brokers)
    return InProcBus()
