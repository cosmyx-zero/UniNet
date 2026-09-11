# UniNet
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Passive, unidirectional, read-only threat detection: behavioural fingerprinting →
**Traffic-Burst Graph** → hybrid AI engine (rules + anomaly + RGAT) → evidence-backed
alerts. No return path, no probing, no payload decryption.

Live demo: <https://uninet-y6g8.onrender.com/>

---

## Architecture

```
 one-way tap / data diode
          │
          ▼
   ingestion/sources         PCAP · NetFlow · IPFIX · sFlow · synthetic
          │   FlowRecord (normalized, unidirectional)
          ▼
   streaming/bus             InProcBus (default) | KafkaBus (one-way topic)
          │
          ▼
   features/extractor        flow · DNS · TLS/JA3 · temporal  ──►  fixed vector
          │                                                   +  behavioural fingerprint
          ▼
   tb_graph/                 burst_builder → graph_builder → graph_store
     ⭐ Traffic-Burst Graph   nodes: host, burst, domain
                             edges: emits, burst_in/out, direction_change, periodic, resolves
          │
          ▼
   detection/                rules · anomaly_model · rgat_model · sequence_model → Alert
          │
          ▼
   api/                      Flask: /api/alerts /api/graph /api/explain /api/ask /api/stream
          │
          ▼
   explainability/  narrative · key factors · burst timeline · fusion bars
   assistant/       offline read-only Q&A over the alert + explanation + subgraph
```

---

## Quick Start

**Docker** (nothing else needed):
```bash
docker compose up            # build + boot; open http://localhost:8000
```

**Python:**
```bash
pip install -e .             # once
uninet                       # train-if-needed → pipeline → dashboard
```

Both open the dashboard at `http://localhost:8000` — default login **`admin` / `uninet`**
(override with `UNINET_AUTH_USER` / `UNINET_AUTH_PASSWORD` env vars, or `--no-auth` for open dev).

### CLI flags

```
--pcap capture.pcap          analyse an offline capture
--seed N                     synthetic data seed
--port N / --host 0.0.0.0    bind address
--no-open                    suppress browser auto-open
--no-auth                    disable login screen (local dev only)
--retrain                    force model retraining
--workers N                  parallel pipeline shards (Phase 5)
--executor process|thread    worker pool type
--live [--interval S]        continuous detection with live console
```

### Other tasks

```bash
python -m uninet.demo                             # CLI alerts table + ground-truth check
python -m uninet.eval.metrics                     # detection metrics
python -m uninet.eval.throughput_bench --flows 400000 --workers 4
python -m pytest                                  # 41 tests
```

---

## Phases

| Phase | Scope | State |
|-------|-------|-------|
| 1 | ingestion → features → TB-Graph → detector → API → dashboard | ✅ |
| 2 | anomaly + RGAT graph + temporal-sequence models → fused threat score | ✅ (real models via `[ml]`; dependency-free fallbacks otherwise) |
| 3 | explainability — narrative, key factors, burst timeline, fusion bars, graph anchors | ✅ |
| 4 | read-only analyst assistant — offline templated Q&A over alert/evidence/graph | ✅ |
| 5 | scale-out: host-partitioned parallel workers + live console | ✅ |

Synthetic benchmark (8 seeds): **precision 1.0, recall 1.0, FP-rate 0.0**.
Single-thread throughput ≈ **9–24k flows/sec**, ~1.3–2× with `--workers 4`.

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | List alerts; filter by `?threat_type=` `?since=` `?host=` |
| `/api/alerts/<id>` | GET | Single alert JSON |
| `/api/explain/<id>` | GET | Full explanation (narrative, signals, timeline, fusion bars) |
| `/api/graph` | GET | Live TB-Graph (nodes + edges) |
| `/api/ask` | POST | Assistant Q&A — body: `{"alert_id": "...", "question": "..."}` |
| `/api/stream` | GET (SSE) | Push new alerts as they are detected |

---

## Project Layout

```
src/uninet/
  schemas/        FlowRecord · TrafficBurst · TBGraph · Alert
  ingestion/      sources/{pcap,netflow,synthetic} → FlowRecord
  streaming/      bus (in-proc | Kafka one-way) + windowed pipeline worker
  features/       flow/DNS/TLS/JA3/temporal extractor + behavioural fingerprint
  baseline/       adaptive per-host profile (false-positive suppression)
  tb_graph/       burst_builder → graph_builder → graph_store  ⭐ core
  detection/      rules · anomaly_model · rgat_model · sequence_model · detector
  explainability/ narrative + factors + timeline
  assistant/      offline read-only Q&A
  api/            Flask endpoints + static dashboard
tests/  eval/  docs/  scripts/  config/
```

---

## Optional Extras

```bash
pip install -e ".[pcap]"    # scapy (live/offline PCAP ingestion)
pip install -e ".[stream]"  # kafka-python (one-way Kafka bus)
pip install -e ".[ml]"      # torch + torch-geometric (real RGAT/GRU models)
pip install -e ".[data]"    # pandas (TII-SSRC-23 dataset loader)
pip install -e ".[dev]"     # pytest + ruff
```

---

## Threat Taxonomy

`benign · ddos · c2_beacon · dga · port_scan · data_exfil · botnet · unknown`

`unknown` = anomalous but unclassified — the zero-day path.

---

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — pipeline and phase-5 scale-out detail
- [`docs/working.md`](docs/working.md) — end-to-end pipeline walkthrough and key concepts
- [`docs/usecases.md`](docs/usecases.md) — analyst, threat-hunter, and platform-engineer workflows
- [`docs/alert-schema.md`](docs/alert-schema.md) — Alert JSON schema reference
- [`docs/readonly-guarantee.md`](docs/readonly-guarantee.md) — sensor read-only contract

---

## References

- UniNet paper — <https://ieeexplore.ieee.org/abstract/document/11063437>
- TB-Graph — <https://www.sciencedirect.com/org/science/article/pii/S1546221825001316>
- NetMamba — <https://arxiv.org/abs/2405.11449v3>
- Data diodes — <https://institutionofelectronics.ac.uk/data-diodes-one-way-check-valves-of-network-security/>
- TII-SSRC-23 Dataset — <https://ieeexplore.ieee.org/document/10262330>
