"""Running per-host baseline of the feature vector (Welford mean/variance).

"Normal traffic builds an adaptive behavioural baseline." A window is only
suspicious if it deviates from *that host's own* history, which is what keeps the
false-positive rate down on quirky-but-benign hosts.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from uninet.features.extractor import FEATURE_KEYS


@dataclass
class _RunningStat:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / self.n) if self.n > 1 else 0.0


@dataclass
class ProfileStore:
    """host -> per-feature running stats."""

    profiles: dict[str, dict[str, _RunningStat]] = field(default_factory=dict)
    warmup: int = 3  # windows before a host's baseline is trusted

    def _host(self, host: str) -> dict[str, _RunningStat]:
        return self.profiles.setdefault(host, {k: _RunningStat() for k in FEATURE_KEYS})

    def observations(self, host: str) -> int:
        stats = self.profiles.get(host)
        return min((s.n for s in stats.values()), default=0) if stats else 0

    def update(self, host: str, vector: dict[str, float]) -> None:
        stats = self._host(host)
        for k in FEATURE_KEYS:
            stats[k].update(float(vector.get(k, 0.0)))

    def zscores(self, host: str, vector: dict[str, float]) -> dict[str, float]:
        stats = self.profiles.get(host)
        if not stats:
            return {k: 0.0 for k in FEATURE_KEYS}
        out: dict[str, float] = {}
        for k in FEATURE_KEYS:
            s = stats[k]
            out[k] = (float(vector.get(k, 0.0)) - s.mean) / s.std if s.std > 1e-9 else 0.0
        return out

    def novelty(self, host: str, vector: dict[str, float]) -> float:
        """Baseline deviation as a bounded score in [0, 1] (0 during warm-up)."""
        if self.observations(host) < self.warmup:
            return 0.0
        z = np.array(list(self.zscores(host, vector).values()))
        rms = float(np.sqrt(np.mean(z ** 2))) if z.size else 0.0
        return float(1.0 - math.exp(-rms / 3.0))

    # ---- persistence ------------------------------------------------- #
    def save(self, path: str | Path) -> None:
        blob = {
            h: {k: [s.n, s.mean, s.m2] for k, s in stats.items()}
            for h, stats in self.profiles.items()
        }
        Path(path).write_text(json.dumps(blob), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> ProfileStore:
        store = cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for h, stats in data.items():
            store.profiles[h] = {
                k: _RunningStat(n=int(v[0]), mean=float(v[1]), m2=float(v[2]))
                for k, v in stats.items()
            }
        return store
