# Models

Trained weights are **not** committed (see `.gitignore`). Regenerate them:

| File | Produced by | Notes |
|------|-------------|-------|
| `anomaly_isoforest.joblib` | `python -m uninet.training.train_anomaly` | Isolation Forest over benign feature vectors. Optional - the detector falls back to the adaptive per-host baseline when it is absent. |
| `rgat.pt` | `python -m uninet.training.train_rgat` | RGAT graph classifier over TB-Graph subgraphs. Requires `pip install -e ".[ml]"`. Optional - the detector falls back to `HeuristicGraphScorer` when it is absent. |

Provenance to record when you train for real: dataset + version, row/window count,
class balance, git commit, date.
