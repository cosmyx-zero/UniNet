"""Base class for all ingestion sources.

A source is *passive*: it reads (a file, a socket, a message topic) and yields
``FlowRecord``s. It never writes to the network. Sub-classes implement
:meth:`stream`.
"""
from __future__ import annotations

import abc
from collections.abc import Iterator

from uninet.schemas.flow import FlowRecord


class FlowSource(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def stream(self) -> Iterator[FlowRecord]:
        """Yield ``FlowRecord``s, ideally in non-decreasing ``start_ts`` order."""
        raise NotImplementedError

    def __iter__(self) -> Iterator[FlowRecord]:
        return self.stream()

    def collect(self, limit: int | None = None) -> list[FlowRecord]:
        out: list[FlowRecord] = []
        for i, rec in enumerate(self.stream()):
            if limit is not None and i >= limit:
                break
            out.append(rec)
        return out
