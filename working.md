# How UniNet Works

UniNet is a **passive network threat-detection system**. It listens on a one-way tap (data diode), processes network flow records through a multi-stage ML pipeline, and surfaces alerts with evidence and explanations — but never acts on the network itself.

---

## End-to-End Pipeline

```
Traffic source (PCAP / NetFlow / IPFIX / sFlow / synthetic)
        │
        ▼
1. Ingestion  ─── normalise → FlowRecord (unidirectional, host-anchored)
        │
        ▼
2. Feature extraction  ─── flow stats · DNS · TLS/JA3 · temporal → fixed vector
                       ─── + behavioural fingerprint per host
        │
        ▼
3. Traffic-Burst Graph (TB-Graph)
        burst_builder  → groups flows into bursts per host
        graph_builder  → nodes: host / burst / domain
                         edges: emits · burst_in/out · direction_change · periodic · resolves
        graph_store    → keeps the live graph in memory
        │
        ▼
4. Detection  (four independent signals fused into one Alert)
        ├── rules          statistical rule engine (port-scan rate, beacon interval, …)
        ├── anomaly_model  Isolation Forest / behavioural baseline novelty
        ├── rgat_model     R-GAT over TB-Graph subgraph (or heuristic fallback)
        └── sequence_model GRU over burst sequence (additive evidence only — does NOT
                           change fused confidence or threat class)

        confidence = 0.7 × strongest_signal + 0.3 × weighted_blend
                     + corroboration_bonus (when rule class == graph hint)

        threat class   → rules first → graph structure → UNKNOWN (zero-day path)
        severity scale → CRITICAL / HIGH / MEDIUM / LOW
        │
        ▼
5. Explainability  ─── narrative · key-factor table · burst timeline · fusion bars
        │
        ▼
6. Read-only Assistant  ─── offline Q&A anchored to alert + explanation + subgraph
        │                    intents: why · confidence · graph · peers · timeline · next
        ▼
7. API + Dashboard  ─── Flask: /api/alerts · /api/graph · /api/explain · /api/ask
                        + /api/stream (SSE live feed) · static React dashboard
```

---

## Key Concepts

### FlowRecord
The normalised, unidirectional unit of work. `flow_parser.py` decides which endpoint is the **local (monitored) host** — private-IP side wins; if both private, `src_ip` is the actor.

### Traffic-Burst Graph (TB-Graph)
The graph aggregates bursts of flows between host pairs. Each window yields a subgraph per host that the R-GAT model reads as a spatial view of behaviour. Burst-level edges encode direction changes, periodic beaconing, and DNS resolution chains.

### Evidence Fusion
The `Detector.assess()` method collects four scores and combines them:

| Signal | Weight (default) | Role |
|--------|-----------------|------|
| Rules | 0.50 | Statistical triggers; primary threat classifier |
| Graph (R-GAT) | 0.30 | Spatial / structural suspicion |
| Anomaly | 0.20 | Unsupervised outlier detection |
| Sequence (GRU) | — | Temporal corroboration only (additive) |

A corroboration bonus (+0.10) is added when rules and graph agree on the same threat class.

### Windowing
`run_pipeline` slices time into fixed `window_seconds` buckets. Each host in a window produces one feature vector, one subgraph, and at most one Alert.

### Scale-Out (Phase 5)
`run_sharded` partitions flows by `hash(local_host) % N` so each worker owns a host's full TB-Graph. `LiveService` drives continuous detection on a configurable interval and hot-swaps the dashboard result.

### Read-Only Guarantee
The assistant, ingestion sources, and API expose **no mutating routes and no network probes**. `tests/test_assistant_readonly.py` enforces this by checking that `assistant/` imports no `socket`, `subprocess`, `requests`, or `scapy`.

---

## Configuration
All tuneable knobs live in `config/config.yaml`:
- `window_seconds` — detection window duration
- `alert_threshold` — minimum fused confidence to emit an Alert
- `fusion_weights` — relative weights for rule / anomaly / graph signals
- `model_path_*` — paths to pre-trained Isolation Forest, R-GAT, and GRU checkpoints

Threat rule thresholds (port-scan rate, beacon interval tolerances, …) live in `config/threat_rules.yaml`.

---

## Running

```bash
# one-shot analysis of a PCAP
python -m uninet path/to/capture.pcap

# live mode: re-runs pipeline every 30 s and serves dashboard
python -m uninet --live --interval 30

# sharded multi-worker run
python -m uninet --workers 4

# start just the API + dashboard
python -m uninet --serve

# benchmark throughput
python -m uninet.eval.throughput_bench --flows 400000 --workers 4
```
