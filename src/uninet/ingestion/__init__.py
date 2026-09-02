"""Ingestion: read-only sources that emit a normalized ``FlowRecord`` stream."""
from uninet.ingestion.sources.base import FlowSource
from uninet.ingestion.sources.netflow import NetFlowCsvSource
from uninet.ingestion.sources.synthetic import SyntheticSource

__all__ = ["FlowSource", "NetFlowCsvSource", "SyntheticSource"]
