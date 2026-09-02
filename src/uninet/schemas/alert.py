"""``Alert`` - the standardized, evidence-backed JSON output of the detector.

This is *the* contract: the API serializes it, the (future) read-only assistant
consumes it, the frontend renders it. Every alert carries the evidence that
produced it and its fused confidence.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum

from pydantic import BaseModel, Field

from uninet.detection.threat_types import ThreatType


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceKind(str, Enum):
    RULE = "rule"          # statistical / heuristic detector
    ANOMALY = "anomaly"    # unsupervised model (unseen behaviour)
    ML = "ml"              # supervised classifier
    GRAPH = "graph"        # TB-Graph / RGAT structural evidence


class Evidence(BaseModel):
    kind: EvidenceKind
    name: str                       # e.g. "beacon_periodicity"
    detail: str                     # human-readable one-liner
    score: float = 0.0              # this signal's contribution in [0, 1]
    data: dict = Field(default_factory=dict)  # supporting numbers / node ids


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_ts: float = Field(default_factory=time.time)

    window_start: float
    window_end: float

    src_host: str
    peers: list[str] = Field(default_factory=list)

    threat_type: ThreatType
    confidence: float               # fused, [0, 1]
    severity: Severity

    title: str
    summary: str
    evidence: list[Evidence] = Field(default_factory=list)

    # TB-Graph anchors so the UI/assistant can pull the relevant subgraph.
    graph_node_ids: list[str] = Field(default_factory=list)

    scores: dict[str, float] = Field(default_factory=dict)  # {rule, anomaly, graph}

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)
