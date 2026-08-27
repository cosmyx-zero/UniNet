"""Graph-based threat scoring over the TB-Graph.

Two implementations behind one interface (:class:`GraphThreatScorer`):

* ``RGATModel`` - a Relational Graph Attention network (PyTorch Geometric).
  Needs the ``ml`` extra. Trained by ``training/train_rgat.py``.
* ``HeuristicGraphScorer`` - a dependency-free message-passing fallback so
  Phase 2 produces a real *graph* signal even without torch installed.

Both return a :class:`GraphScore`: a scalar suspicion in [0, 1], a threat hint
derived from graph structure, and the burst nodes that drove the score
(evidence anchors for the explainer / assistant).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from uninet.detection.threat_types import ThreatType
from uninet.schemas.graph import NodeType, RelationType
from uninet.utils import clamp01, shannon_entropy

try:  # optional heavy stack
    import torch  # type: ignore

    _TORCH = True
except ImportError:  # pragma: no cover - env dependent
    _TORCH = False

_BURST_FEATURES = [
    "byte_count", "packet_count", "flow_count", "duration",
    "dir_code", "intra_periodicity", "unique_dst_ports", "mean_flow_bytes",
]
_RELATIONS = [r.value for r in RelationType]


@dataclass
class GraphScore:
    score: float
    threat_hint: ThreatType
    top_nodes: list[str] = field(default_factory=list)
    rationale: str = ""


def burst_feature_matrix(subgraph, burst_nodes: list[str]) -> np.ndarray:
    rows = []
    for n in burst_nodes:
        d = subgraph.nodes[n]
        rows.append([
            np.log1p(d.get("byte_count", 0.0)),
            np.log1p(d.get("packet_count", 0.0)),
            np.log1p(d.get("flow_count", 0.0)),
            float(d.get("duration", 0.0)),
            float(d.get("dir_code", 0.0)),
            float(d.get("intra_periodicity", 0.0)),
            np.log1p(d.get("unique_dst_ports", 0.0)),
            np.log1p(d.get("mean_flow_bytes", 0.0)),
        ])
    return np.asarray(rows, dtype=float) if rows else np.zeros((0, len(_BURST_FEATURES)))


class GraphThreatScorer:
    """Facade that picks RGAT if a trained model is present, else the heuristic."""

    def __init__(self, model_path: str | Path | None = None) -> None:
        self._rgat: RGATModel | None = None
        if model_path and _TORCH and Path(model_path).is_file():
            try:
                self._rgat = RGATModel.load(model_path)
            except Exception:  # pragma: no cover - corrupt/incompatible checkpoint
                self._rgat = None
        self._heuristic = HeuristicGraphScorer()

    @property
    def backend(self) -> str:
        return "rgat" if self._rgat is not None else "heuristic"

    def score(self, subgraph, host_ip: str) -> GraphScore:
        if self._rgat is not None:
            try:
                return self._rgat.score(subgraph, host_ip)
            except Exception:  # pragma: no cover - fall back rather than crash
                pass
        return self._heuristic.score(subgraph, host_ip)


class HeuristicGraphScorer:
    """Message passing on burst nodes + structural threat hinting."""

    ITERS = 2

    def score(self, subgraph, host_ip: str) -> GraphScore:
        burst_nodes = [
            n for n, d in subgraph.nodes(data=True)
            if d.get("ntype") == NodeType.BURST.value and d.get("host") == host_ip
        ]
        if not burst_nodes:
            return GraphScore(0.0, ThreatType.BENIGN, [], "no bursts for host")

        X = burst_feature_matrix(subgraph, burst_nodes)
        idx = {n: i for i, n in enumerate(burst_nodes)}

        # --- base per-burst suspicion ---------------------------------
        def col(name: str) -> np.ndarray:
            return X[:, _BURST_FEATURES.index(name)]

        base = clamp01_vec(
            0.30 * _minmax(col("flow_count"))
            + 0.25 * _minmax(col("byte_count"))
            + 0.20 * _minmax(col("unique_dst_ports"))
            + 0.25 * col("intra_periodicity")
        )

        # --- propagate along burst<->burst edges ---------------------
        chain_rels = {
            RelationType.BURST_IN.value, RelationType.BURST_OUT.value,
            RelationType.PERIODIC.value, RelationType.DIRECTION_CHANGE.value,
        }
        neighbours: dict[int, list[int]] = {i: [] for i in range(len(burst_nodes))}
        periodic_edges = dir_change_edges = 0
        for u, v, d in subgraph.edges(data=True):
            if u in idx and v in idx and d.get("rel") in chain_rels:
                neighbours[idx[u]].append(idx[v])
                neighbours[idx[v]].append(idx[u])
                periodic_edges += d.get("rel") == RelationType.PERIODIC.value
                dir_change_edges += d.get("rel") == RelationType.DIRECTION_CHANGE.value

        s = base.copy()
        for _ in range(self.ITERS):
            nxt = s.copy()
            for i, nb in neighbours.items():
                if nb:
                    nxt[i] = 0.6 * s[i] + 0.4 * float(np.mean(s[nb]))
            s = nxt

        # --- structural context -------------------------------------
        domain_nodes = [
            d.get("name", n) for n, d in subgraph.nodes(data=True)
            if d.get("ntype") == NodeType.DOMAIN.value
        ]
        dom_entropy = (
            float(np.mean([shannon_entropy(dn.split(".")[0]) for dn in domain_nodes]))
            if domain_nodes else 0.0
        )

        host_score = clamp01(0.7 * float(s.max()) + 0.3 * float(s.mean()))
        struct_boost = clamp01(
            0.10 * min(periodic_edges, 5) / 5
            + 0.10 * min(dir_change_edges, 5) / 5
            + 0.10 * _minmax_scalar(dom_entropy, 2.5, 4.0)
        )
        host_score = clamp01(host_score + struct_boost)

        hint, why = self._hint(
            X, col, periodic_edges, len(domain_nodes), dom_entropy, host_score
        )
        top = [burst_nodes[i] for i in np.argsort(-s)[:3]]
        return GraphScore(host_score, hint, top, why)

    @staticmethod
    def _hint(X, col, periodic_edges, n_domains, dom_entropy, score):
        if score < 0.45:
            return ThreatType.BENIGN, "graph activity within normal structural bounds"
        max_ports = float(col("unique_dst_ports").max())
        max_flows = float(np.expm1(col("flow_count").max()))
        max_bytes = float(np.expm1(col("byte_count").max()))
        mean_bytes = float(np.expm1(col("byte_count").mean()))
        if periodic_edges >= 2 and mean_bytes < 8000:
            return ThreatType.C2_BEACON, f"{periodic_edges} periodic burst links, small regular check-ins"
        if n_domains >= 12 and dom_entropy >= 3.3:
            return ThreatType.DGA, f"{n_domains} resolved domains, mean label entropy {dom_entropy:.2f}"
        if np.expm1(max_ports) >= 50:
            return ThreatType.PORT_SCAN, f"burst fans out to {np.expm1(max_ports):.0f} ports"
        if max_flows >= 500:
            return ThreatType.DDOS, f"burst concentrates {max_flows:.0f} flows on one peer"
        if max_bytes >= 5e7:
            return ThreatType.DATA_EXFIL, f"burst moves {max_bytes / 1e6:.0f} MB to one peer"
        return ThreatType.UNKNOWN, "abnormal burst structure, no known-class match"


# ---- helpers ------------------------------------------------------------ #
def clamp01_vec(a: np.ndarray) -> np.ndarray:
    return np.clip(a, 0.0, 1.0)


def _minmax(a: np.ndarray) -> np.ndarray:
    if a.size == 0:
        return a
    lo, hi = float(a.min()), float(a.max())
    return (a - lo) / (hi - lo) if hi > lo else np.zeros_like(a)


def _minmax_scalar(x: float, lo: float, hi: float) -> float:
    return clamp01((x - lo) / (hi - lo)) if hi > lo else 0.0


# ====================================================================== #
#  Real RGAT (optional - requires torch + torch-geometric)
# ====================================================================== #
if _TORCH:  # pragma: no cover - exercised only when the ml extra is installed
    import torch
    import torch.nn.functional as F
    from torch import nn

    _THREATS = [t for t in ThreatType]

    class _RGATNet(nn.Module):
        def __init__(self, in_dim: int, hidden: int = 64, heads: int = 4):
            super().__init__()
            from torch_geometric.nn import RGATConv, global_mean_pool

            self.g1 = RGATConv(in_dim, hidden, num_relations=len(_RELATIONS), heads=heads, concat=False)
            self.g2 = RGATConv(hidden, hidden, num_relations=len(_RELATIONS), heads=heads, concat=False)
            self.head = nn.Linear(hidden, len(_THREATS))
            self._pool = global_mean_pool

        def forward(self, x, edge_index, edge_type, batch):
            x = F.relu(self.g1(x, edge_index, edge_type))
            x = F.dropout(x, p=0.2, training=self.training)
            x = F.relu(self.g2(x, edge_index, edge_type))
            return self.head(self._pool(x, batch))

    class RGATModel:
        def __init__(self, net: _RGATNet | None = None, in_dim: int = len(_BURST_FEATURES)):
            self.in_dim = in_dim
            self.net = net or _RGATNet(in_dim)
            self.net.eval()

        # -- graph conversion ---------------------------------------
        @staticmethod
        def to_tensors(subgraph, host_ip: str):
            burst_nodes = [
                n for n, d in subgraph.nodes(data=True)
                if d.get("ntype") == NodeType.BURST.value and d.get("host") == host_ip
            ]
            if not burst_nodes:
                return None
            idx = {n: i for i, n in enumerate(burst_nodes)}
            X = burst_feature_matrix(subgraph, burst_nodes)
            src, dst, etype = [], [], []
            for u, v, d in subgraph.edges(data=True):
                if u in idx and v in idx and d.get("rel") in _RELATIONS:
                    src.append(idx[u]); dst.append(idx[v])
                    etype.append(_RELATIONS.index(d["rel"]))
            edge_index = torch.tensor([src, dst], dtype=torch.long) if src else torch.zeros((2, 0), dtype=torch.long)
            return (
                torch.tensor(X, dtype=torch.float32),
                edge_index,
                torch.tensor(etype, dtype=torch.long) if etype else torch.zeros((0,), dtype=torch.long),
            )

        def score(self, subgraph, host_ip: str) -> GraphScore:
            packed = self.to_tensors(subgraph, host_ip)
            if packed is None:
                return GraphScore(0.0, ThreatType.BENIGN, [], "no bursts for host")
            x, edge_index, edge_type = packed
            batch = torch.zeros(x.size(0), dtype=torch.long)
            with torch.no_grad():
                logits = self.net(x, edge_index, edge_type, batch)
                probs = F.softmax(logits, dim=-1).squeeze(0)
            k = int(torch.argmax(probs))
            hint = _THREATS[k]
            benign_i = _THREATS.index(ThreatType.BENIGN)
            score = float(1.0 - probs[benign_i])
            return GraphScore(score, hint, [], f"RGAT p={float(probs[k]):.2f} for {hint.value}")

        def save(self, path: str | Path) -> None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            torch.save({"state_dict": self.net.state_dict(), "in_dim": self.in_dim}, path)

        @classmethod
        def load(cls, path: str | Path) -> RGATModel:
            blob = torch.load(path, map_location="cpu")
            m = cls(in_dim=blob.get("in_dim", len(_BURST_FEATURES)))
            m.net.load_state_dict(blob["state_dict"])
            m.net.eval()
            return m

else:  # torch not installed - keep the name importable

    class RGATModel:  # type: ignore
        def __init__(self, *_, **__):
            raise RuntimeError('RGATModel needs the ml extra: pip install -e ".[ml]"')

        @classmethod
        def load(cls, *_a, **_k):
            raise RuntimeError('RGATModel needs the ml extra: pip install -e ".[ml]"')
