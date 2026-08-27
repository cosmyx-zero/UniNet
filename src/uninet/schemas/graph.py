"""TB-Graph schema: node types, relation (edge) types, and a serializable view.

The live graph is a ``networkx.MultiDiGraph`` (see ``tb_graph.graph_store``); these
models are the typed vocabulary for building it and the JSON shape the API/frontend
consume.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    HOST = "host"
    BURST = "burst"
    DOMAIN = "domain"
    ALERT = "alert"


class RelationType(str, Enum):
    EMITS = "emits"                       # host      -> burst
    BURST_IN = "burst_in"                 # burst     -> next burst (inbound follows)
    BURST_OUT = "burst_out"               # burst     -> next burst (outbound follows)
    DIRECTION_CHANGE = "direction_change" # burst     -> next burst, direction flipped
    PERIODIC = "periodic"                 # burst     -> burst, regular inter-arrival
    RESOLVES = "resolves"                 # burst     -> domain (DNS lookup)
    RAISED_ON = "raised_on"               # alert     -> host / burst


class Node(BaseModel):
    id: str
    type: NodeType
    attrs: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    src: str
    dst: str
    rel: RelationType
    attrs: dict[str, Any] = Field(default_factory=dict)


class TBGraphView(BaseModel):
    """Flat, front-end friendly serialization of a (sub)graph."""

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    def node_count_by_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.nodes:
            out[n.type.value] = out.get(n.type.value, 0) + 1
        return out
