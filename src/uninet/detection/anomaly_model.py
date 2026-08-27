"""Unsupervised anomaly detector - the "previously-unseen behaviour" path.

Isolation Forest over the log-scaled, standardized feature vector. Produces a
score in [0, 1] (higher = more anomalous). When no trained model is available the
detector falls back to the per-host adaptive baseline (``baseline.ProfileStore``),
so the pipeline still runs end-to-end out of the box.
"""
from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from uninet.features.extractor import FEATURE_KEYS


def _prep(x: np.ndarray) -> np.ndarray:
    return np.log1p(np.clip(x, 0.0, None))


class AnomalyModel:
    def __init__(self) -> None:
        self._scaler = None
        self._clf = None
        self._offset = 0.0   # 5th-percentile decision_function on benign training data
        self.feature_keys = list(FEATURE_KEYS)

    @property
    def is_fitted(self) -> bool:
        return self._clf is not None

    # ------------------------------------------------------------------ #
    def fit(self, vectors: list[np.ndarray] | np.ndarray, random_state: int = 0) -> AnomalyModel:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        X = _prep(np.atleast_2d(np.asarray(vectors, dtype=float)))
        self._scaler = StandardScaler().fit(X)
        Xs = self._scaler.transform(X)
        self._clf = IsolationForest(
            n_estimators=300, contamination=0.01, random_state=random_state
        ).fit(Xs)
        # Calibrate against the benign training floor: a window only scores above
        # 0.5 once it is more isolated than ~99% of benign training windows, so a
        # standalone anomaly alert means "unlike anything seen before".
        train_d = self._clf.decision_function(Xs)
        self._offset = float(np.quantile(train_d, 0.01))
        return self

    def score(self, vector: np.ndarray) -> float:
        """Anomaly score in [0, 1]; 0.0 if the model is not fitted."""
        if not self.is_fitted:
            return 0.0
        x = _prep(np.asarray(vector, dtype=float).reshape(1, -1))
        d = float(self._clf.decision_function(self._scaler.transform(x))[0])
        return 1.0 / (1.0 + math.exp(15.0 * (d - self._offset)))

    # ---- persistence ------------------------------------------------- #
    def save(self, path: str | Path) -> None:
        import joblib

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "scaler": self._scaler, "clf": self._clf,
                "offset": self._offset, "feature_keys": self.feature_keys,
            },
            path,
        )

    @classmethod
    def load(cls, path: str | Path) -> AnomalyModel:
        import joblib

        blob = joblib.load(path)
        m = cls()
        m._scaler = blob["scaler"]
        m._clf = blob["clf"]
        m._offset = float(blob.get("offset", 0.0))
        m.feature_keys = blob.get("feature_keys", list(FEATURE_KEYS))
        return m

    @classmethod
    def load_or_none(cls, path: str | Path) -> AnomalyModel | None:
        try:
            return cls.load(path)
        except (FileNotFoundError, OSError, KeyError):
            return None
