"""The threat taxonomy UniNet reports against.

Six named threat classes plus BENIGN and UNKNOWN. UNKNOWN is what the anomaly
detector raises when behaviour is clearly abnormal but matches no known class -
this is the "zero-day detection without signatures" path.
"""
from __future__ import annotations

from enum import Enum


class ThreatType(str, Enum):
    BENIGN = "benign"
    DDOS = "ddos"                 # volumetric flooding
    C2_BEACON = "c2_beacon"       # command-and-control check-in
    DGA = "dga"                   # algorithmically-generated domain lookups
    PORT_SCAN = "port_scan"       # host / service reconnaissance
    DATA_EXFIL = "data_exfil"     # large sustained egress
    BOTNET = "botnet"             # coordinated multi-host malicious activity
    UNKNOWN = "unknown"           # anomalous, unclassified (possible zero-day)

    @property
    def is_actionable(self) -> bool:
        return self not in (ThreatType.BENIGN,)
