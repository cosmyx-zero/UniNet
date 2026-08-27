"""Holds the live TB-Graph and answers the queries the API / detector / UI need.

In-memory ``networkx`` now; the interface (add, subgraph_for_host, to_view) is what
a future graph database would implement.
"""
from __future__ import annotations

import networkx as nx

from uninet.schemas.graph import Edge, Node, NodeType, RelationType, TBGraphView


class TBGraphStore:
    def __init__(self, graph: nx.MultiDiGraph | None = None) -> None:
        self.g: nx.MultiDiGraph = graph if graph is not None else nx.MultiDiGraph()

    # ---- mutation --------------------------------------------------- #
    def merge(self, other: nx.MultiDiGraph) -> None:
        self.g.add_nodes_from(other.nodes(data=True))
        self.g.add_edges_from(other.edges(keys=True, data=True))

    # ---- queries -------------------------------------------------- #
    def hosts(self) -> list[str]:
        return [d["ip"] for _, d in self.g.nodes(data=True) if d.get("ntype") == NodeType.HOST.value]

    def burst_ids_for_host(self, host_ip: str) -> list[str]:
        return [
            n for n, d in self.g.nodes(data=True)
            if d.get("ntype") == NodeType.BURST.value and d.get("host") == host_ip
        ]

    def subgraph_for_host(self, host_ip: str, radius: int = 2) -> nx.MultiDiGraph:
        seeds = {f"host:{host_ip}", *self.burst_ids_for_host(host_ip)}
        seeds = {n for n in seeds if self.g.has_node(n)}
        nodes: set[str] = set(seeds)
        frontier = set(seeds)
        for _ in range(radius):
            nxt: set[str] = set()
            for n in frontier:
                nxt.update(self.g.successors(n))
                nxt.update(self.g.predecessors(n))
            nodes.update(nxt)
            frontier = nxt
        return self.g.subgraph(nodes).copy()

    # ---- serialization ----------------------------------------------- #
    def to_view(self, graph: nx.MultiDiGraph | None = None) -> TBGraphView:
        g = graph if graph is not None else self.g
        nodes = [
            Node(id=n, type=NodeType(d.get("ntype", "burst")),
                 attrs={k: v for k, v in d.items() if k != "ntype"})
            for n, d in g.nodes(data=True)
        ]
        edges = [
            Edge(src=u, dst=v, rel=RelationType(d.get("rel", "emits")),
                 attrs={k: val for k, val in d.items() if k != "rel"})
            for u, v, d in g.edges(data=True)
        ]
        return TBGraphView(nodes=nodes, edges=edges)

    def stats(self) -> dict[str, int]:
        by_type: dict[str, int] = {}
        for _, d in self.g.nodes(data=True):
            t = d.get("ntype", "?")
            by_type[t] = by_type.get(t, 0) + 1
        return {"nodes": self.g.number_of_nodes(), "edges": self.g.number_of_edges(), **by_type}
