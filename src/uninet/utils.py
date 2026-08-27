"""Small numeric helpers shared across feature extraction and detection."""
from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence

import numpy as np


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits/char of ``text`` (0.0 for empty/1-char strings)."""
    text = (text or "").strip().lower()
    if len(text) < 2:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def coefficient_of_variation(values: Sequence[float]) -> float:
    """std / mean. Returns 0.0 for a perfectly regular series, inf if mean == 0."""
    arr = np.asarray(list(values), dtype=float)
    if arr.size < 2:
        return 0.0
    mean = float(arr.mean())
    if mean == 0.0:
        return float("inf")
    return float(arr.std() / mean)


def periodicity_score(timestamps: Sequence[float], min_points: int = 3) -> float:
    """Regularity of event times in [0, 1]. 1.0 == perfectly periodic (beacon-like).

    Derived from the coefficient of variation of inter-arrival gaps:
    score = 1 / (1 + CoV), so CoV=0 -> 1.0 and large jitter -> ~0.
    """
    ts = sorted(float(t) for t in timestamps)
    if len(ts) < max(min_points, 2):
        return 0.0
    gaps = np.diff(ts)
    if np.all(gaps == 0):
        return 0.0
    cov = coefficient_of_variation(gaps)
    if not math.isfinite(cov):
        return 0.0
    return float(1.0 / (1.0 + cov))


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def ramp(value: float, lo: float, hi: float) -> float:
    """Linear 0->1 ramp: 0 below ``lo``, 1 at/above ``hi``."""
    if hi <= lo:
        return 1.0 if value >= hi else 0.0
    return clamp01((value - lo) / (hi - lo))


def safe_ratio(numerator: float, denominator: float, default: float = 0.0) -> float:
    return numerator / denominator if denominator else default


def registrable_label(domain: str) -> str:
    """Best-effort second-level label of a domain (no PSL dependency).

    ``xz9q2p1k.example.com`` -> ``xz9q2p1k`` is what DGA scoring cares about; here
    we take the left-most label, which is where generated names put their entropy.
    """
    domain = (domain or "").strip(".").lower()
    if not domain:
        return ""
    return domain.split(".")[0]


def mean(values: Iterable[float], default: float = 0.0) -> float:
    vals = list(values)
    return float(np.mean(vals)) if vals else default
