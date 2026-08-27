"""UniNet - AI-based detection of cyber threats in unidirectional IP traffic.

Pipeline (Phase 1 + Phase 2):

    ingestion  ->  features  ->  tb_graph  ->  detection  ->  api / dashboard
                                    (RGAT + anomaly + rules, fused)

Everything is passive and read-only: no return path, no probing, no payload
decryption, no mitigation commands.
"""

__version__ = "0.1.0"

# Threat taxonomy is part of the public surface.
from uninet.detection.threat_types import ThreatType

__all__ = ["ThreatType", "__version__"]
