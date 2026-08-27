# UniNet architecture (Phase 1 + Phase 2)

```
 one-way tap / data diode
          │
          ▼
   ingestion/sources         PCAP · NetFlow · IPFIX · sFlow · synthetic
          │   FlowRecord (normalized, unidirectional)
          ▼
   streaming/bus             InProcBus (default) │ KafkaBus (one-way topic)
          │
          ▼
   features/extractor        flow · DNS · TLS/JA3 · temporal  ──►  fixed vector
          │                                                   +  behavioural fingerprint
          ▼
   tb_graph/                 burst_builder → graph_builder → graph_store
     ⭐ Traffic-Burst graph   nodes: host, burst, domain
                             edges: emits, burst_in/out, direction_change, periodic, resolves
          │
          ▼
   detection/                rules (statistical)  ┐
                             anomaly_model (IsoForest / baseline)  ├─ evidence fusion ─► Alert
                             rgat_model (RGAT │ heuristic graph)   ┘
          │
          ▼
   api/app.py                Flask: /api/alerts /api/graph /api/explain  + dashboard
          │
          ▼
   explainability/ , assistant/   (Phase 3 / 4 — read-only)
```

## Windowing

`run_pipeline` processes flows in fixed `window_seconds` slices. Within a window,
flows are grouped by local host; each host yields one feature vector, a set of
bursts, a merged TB-Graph subgraph, and (if fused confidence ≥ threshold) one
`Alert`.

## Evidence fusion

```
confidence = w_rule·rule_score + w_anom·anomaly_score + w_graph·graph_score
             + corroboration_bonus     # when rule class == graph hint
```

Weights come from `config/config.yaml` (`fusion_weights`, renormalized to sum 1).
Threat class is taken from the most interpretable signal that fired: rules →
graph structure → `UNKNOWN` for a pure anomaly (the zero-day path).

## Read-only guarantee

`src/uninet/assistant/` must not import `socket`, `subprocess`, `requests`,
`scapy`, … — enforced by `tests/test_assistant_readonly.py`. The API exposes no
mutating routes; `POST /api/ask` returns `501` until Phase 4.
