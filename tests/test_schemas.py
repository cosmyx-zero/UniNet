from uninet.detection.threat_types import ThreatType
from uninet.schemas.alert import Alert, Evidence, EvidenceKind, Severity
from uninet.schemas.flow import FlowRecord, Protocol


def test_flowrecord_roundtrip_and_props():
    r = FlowRecord(
        src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=51000, dst_port=53,
        protocol=Protocol.UDP, start_ts=100.0, end_ts=100.2, packets=2, bytes=180,
        dns_qname="example.com", dns_rcode=0,
    )
    assert r.is_dns and not r.is_tls
    assert abs(r.duration - 0.2) < 1e-9
    again = FlowRecord.model_validate_json(r.model_dump_json())
    assert again == r


def test_end_ts_not_before_start():
    r = FlowRecord(src_ip="a", dst_ip="b", start_ts=10.0, end_ts=5.0)
    assert r.end_ts == 10.0


def test_alert_json_shape():
    a = Alert(
        window_start=0.0, window_end=60.0, src_host="10.0.0.9",
        threat_type=ThreatType.DGA, confidence=0.77, severity=Severity.HIGH,
        title="t", summary="s",
        evidence=[Evidence(kind=EvidenceKind.RULE, name="dga_domain_entropy",
                           detail="d", score=0.7)],
    )
    blob = a.model_dump(mode="json")
    assert blob["threat_type"] == "dga"
    assert blob["evidence"][0]["kind"] == "rule"
