from uninet.schemas.burst import Direction
from uninet.schemas.flow import FlowRecord, Protocol
from uninet.schemas.graph import RelationType
from uninet.tb_graph.burst_builder import BurstBuilder
from uninet.tb_graph.graph_builder import GraphBuilder
from uninet.tb_graph.graph_store import TBGraphStore


def _flow(src, dst, ts, dur=0.2, b=800, dport=443):
    return FlowRecord(src_ip=src, dst_ip=dst, src_port=45000, dst_port=dport,
                      protocol=Protocol.TCP, start_ts=ts, end_ts=ts + dur,
                      packets=6, bytes=b)


def test_bursts_split_on_idle_gap():
    host, peer = "10.0.0.5", "93.1.1.1"
    flows = [_flow(host, peer, t) for t in (0.0, 0.5, 1.0)]          # burst 1
    flows += [_flow(host, peer, t) for t in (30.0, 30.4, 30.8)]      # burst 2 (gap > 2s)
    bursts = BurstBuilder(gap_seconds=2.0).build(flows, host)
    assert len(bursts) == 2
    assert bursts[0].flow_count == 3 and bursts[1].flow_count == 3
    assert bursts[0].direction == Direction.OUTBOUND


def test_direction_change_and_periodic_edges():
    host, peer = "10.0.0.6", "198.51.100.9"
    flows = []
    for k in range(5):                       # regular outbound check-ins every 30s
        flows.append(_flow(host, peer, k * 30.0, b=500))
    for k in range(5):                       # interleaved inbound replies
        flows.append(_flow(peer, host, k * 30.0 + 1.0, b=400))
    bursts = BurstBuilder(gap_seconds=2.0).build(flows, host)
    g = GraphBuilder(periodicity_cov_threshold=0.4, min_chain=3).build(bursts)

    rels = {d["rel"] for _, _, d in g.edges(data=True)}
    assert RelationType.EMITS.value in rels
    assert RelationType.PERIODIC.value in rels or RelationType.DIRECTION_CHANGE.value in rels

    store = TBGraphStore(g)
    view = store.to_view(store.subgraph_for_host(host))
    assert any(n.type.value == "burst" for n in view.nodes)
    assert any(n.type.value == "host" for n in view.nodes)
