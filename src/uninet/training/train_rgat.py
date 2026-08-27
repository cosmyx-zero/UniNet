"""Train the RGAT graph classifier over TB-Graph subgraphs.

Requires the ``ml`` extra (torch + torch-geometric). If torch is missing this
prints a skip notice and exits 0 - the pipeline then uses the heuristic graph
scorer, so Phase 2 still functions.

    python -m uninet.training.train_rgat --epochs 40
    python -m uninet.training.train_rgat --dataset tii --limit 100000
"""
from __future__ import annotations

import argparse

from uninet.config import load_settings
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.training._samples import Sample, build_samples

try:
    import torch  # type: ignore

    _TORCH = True
except ImportError:
    _TORCH = False


def _collect_samples(dataset: str, limit: int) -> list[Sample]:
    if dataset == "tii":
        from uninet.datasets.tii_ssrc23 import load_tii_ssrc23

        recs, labels = load_tii_ssrc23(limit=limit)
        return build_samples(recs, flow_labels=labels)
    samples: list[Sample] = []
    for seed in range(16):
        src = SyntheticSource(seed=seed)
        samples += build_samples(src.collect(), host_labels=src.labels)
    return samples


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", choices=["synthetic", "tii"], default="synthetic")
    p.add_argument("--limit", type=int, default=100000)
    p.add_argument("--epochs", type=int, default=40)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)

    if not _TORCH:
        print('torch not installed - skipping RGAT training. Install: pip install -e ".[ml]"')
        return 0

    import torch.nn.functional as F
    from torch_geometric.data import Data
    from torch_geometric.loader import DataLoader

    from uninet.detection.rgat_model import _BURST_FEATURES, RGATModel

    settings = load_settings()
    samples = _collect_samples(args.dataset, args.limit)
    threats = list(ThreatType)
    label_idx = {t: i for i, t in enumerate(threats)}

    graphs: list[Data] = []
    for s in samples:
        packed = RGATModel.to_tensors(s.subgraph, s.host)
        if packed is None:
            continue
        x, edge_index, edge_type = packed
        if x.size(0) == 0:
            continue
        graphs.append(
            Data(x=x, edge_index=edge_index, edge_type=edge_type,
                 y=torch.tensor([label_idx[s.label]], dtype=torch.long))
        )

    if len(graphs) < 8:
        print(f"not enough graph samples ({len(graphs)})")
        return 1

    split = max(1, int(0.8 * len(graphs)))
    train_dl = DataLoader(graphs[:split], batch_size=16, shuffle=True)
    val_dl = DataLoader(graphs[split:], batch_size=32)

    model = RGATModel(in_dim=len(_BURST_FEATURES))
    opt = torch.optim.Adam(model.net.parameters(), lr=args.lr, weight_decay=5e-4)

    for epoch in range(1, args.epochs + 1):
        model.net.train()
        total = 0.0
        for batch in train_dl:
            opt.zero_grad()
            out = model.net(batch.x, batch.edge_index, batch.edge_type, batch.batch)
            loss = F.cross_entropy(out, batch.y.view(-1))
            loss.backward()
            opt.step()
            total += float(loss) * batch.num_graphs
        if epoch % 10 == 0 or epoch == args.epochs:
            acc = _accuracy(model, val_dl) if len(graphs) > split else float("nan")
            print(f"epoch {epoch:3d}  loss {total / split:.4f}  val_acc {acc:.3f}")

    out = args.out or settings.model_path_rgat
    model.save(out)
    print(f"saved RGAT -> {out}")
    return 0


def _accuracy(model, dl) -> float:
    import torch

    model.net.eval()
    correct = n = 0
    with torch.no_grad():
        for batch in dl:
            pred = model.net(batch.x, batch.edge_index, batch.edge_type, batch.batch).argmax(-1)
            correct += int((pred == batch.y.view(-1)).sum())
            n += batch.num_graphs
    return correct / n if n else float("nan")


if __name__ == "__main__":
    raise SystemExit(main())
