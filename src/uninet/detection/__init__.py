<<<<<<< HEAD
"""Hybrid detection engine: rules + anomaly + RGAT graph + temporal sequence,
fused into one Alert."""
from uninet.detection.detector import Detector, DetectorConfig
from uninet.detection.sequence_model import SequenceThreatScorer
from uninet.detection.threat_types import ThreatType

__all__ = ["Detector", "DetectorConfig", "SequenceThreatScorer", "ThreatType"]
=======
"""Hybrid detection engine: rules + anomaly model + RGAT, fused into one Alert."""
from uninet.detection.detector import Detector, DetectorConfig
from uninet.detection.threat_types import ThreatType

__all__ = ["Detector", "DetectorConfig", "ThreatType"]
>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
