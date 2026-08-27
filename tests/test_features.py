from uninet.features.extractor import FEATURE_KEYS, FeatureExtractor
from uninet.schemas.flow import FlowRecord, Protocol
from uninet.tb_graph.burst_builder import BurstBuilder
from uninet.utils import periodicity_score, shannon_entropy


def _dns(host, name, ts, rcode=0):
    return FlowRecord(src_ip=host, dst_ip="10.0.0.1", src_port=40000, dst_port=53,
                      protocol=Protocol.UDP, start_ts=ts, end_ts=ts + 0.05,
                      packets=2, bytes=160, dns_qname=name, dns_rcode=rcode)


def test_periodicity_regular_vs_jittery():
    regular = [i * 30.0 for i in range(10)]
    jittery = [0, 5, 40, 43, 120, 121, 300]
    assert periodicity_score(regular) > 0.95
    assert periodicity_score(jittery) < periodicity_score(regular)


def test_dga_entropy_higher_for_random_labels():
    assert shannon_entropy("google") < shannon_entropy("x7f9q2z1k8w3")


def test_extractor_vector_keys_and_dns_features():
    host = "10.0.0.42"
    flows = [_dns(host, f"{'abc123xyz' + str(i)}.top", 100 + i * 2, rcode=3) for i in range(20)]
    bursts = BurstBuilder(gap_seconds=2.0).build(flows, host)
    feats = FeatureExtractor(60).extract(host, flows, bursts, 100.0, 160.0)

    assert list(feats.vector.keys()) == FEATURE_KEYS
    assert feats.vector["dns_query_count"] == 20
    assert feats.vector["unique_domain_count"] == 20
    assert feats.vector["nxdomain_ratio"] == 1.0
    assert feats.vector["mean_domain_entropy"] > 2.5
    assert feats.as_array().shape == (len(FEATURE_KEYS),)
