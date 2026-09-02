# UniNet
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

SIH26145 · Team Cosmyx Zero · Theme: Blockchain & Cybersecurity

Passive, unidirectional, read-only threat detection: behavioural fingerprinting →
**Traffic-Burst Graph** → hybrid AI engine (rules + anomaly + RGAT) → evidence-backed
alerts. No return path, no probing, no payload decryption.

---

<<<<<<< HEAD
## Status — all 5 phases implemented

| Phase | Scope | State |
|-------|-------|-------|
| 1 | ingestion → features → TB-Graph → detector → API → interactive dashboard (session login) | ✅ |
| 2 | anomaly + RGAT graph + temporal-sequence models → fused threat score | ✅ (real models via `[ml]`; dependency-free fallbacks otherwise) |
| 3 | explainability — narrative, key factors, burst timeline, fusion bars, graph anchors | ✅ (`GET /api/explain/<id>`) |
| 4 | read-only analyst assistant — offline templated Q&A over alert/evidence/graph | ✅ (`POST /api/ask {question, alert_id?}`) |
| 5 | scale-out: host-partitioned parallel workers + live console | ✅ (`--workers N`, `--live`) |

On the built-in synthetic scenarios (8 seeds): **precision 1.0, recall 1.0, FP-rate 0.0**;
single-thread throughput ≈ **9–24k flows/sec**, ~1.3–2× with `--workers 4`. Defensible
numbers — see `python -m uninet.eval.metrics` / `...throughput_bench`.

> **"Read-only" is an architecture property** — the sensor is a passive tap / data
> diode with no return path. The console itself is fully interactive.

## Run it — one command

**Docker** (nothing else needed):
```bash
docker compose up            # build + boot; open http://localhost:8000
```

**or Python:**
```bash
pip install -e .             # once
uninet                       # train-if-needed → run pipeline → open dashboard
```

Both open the **dashboard at http://localhost:8000** — login **`admin` / `uninet`**
(override with `UNINET_AUTH_USER` / `UNINET_AUTH_PASSWORD`; `uninet --no-auth` for open dev).

`uninet` flags: `--pcap capture.pcap`, `--seed N`, `--port N`, `--host 0.0.0.0`,
`--no-open`, `--no-auth`, `--retrain`,
`--workers N` / `--executor process|thread` (Phase 5 parallel pipeline),
`--live [--interval S]` (keep refreshing detections — live console).

The dashboard has an **Alerts** tab and a **Clients** tab (per-host view: IPs,
ports, behavioural fingerprint, alert status). Top stat cards, severity bars and
threat chips are click-to-filter. TB-Graph nodes are labelled with IPs / domains;
hover a burst for its ports.

### Other tasks

```bash
python -m uninet.demo                     # CLI: alerts table + ground-truth check (no server)
python -m uninet.eval.metrics             # detection metrics
python -m uninet.eval.throughput_bench --flows 400000 --workers 4
python -m pytest                          # 41 tests
```

Optional extras: `.[dev]` (pytest/ruff), `.[pcap]` (scapy), `.[stream]` (Kafka one-way bus),
`.[ml]` (torch + torch-geometric for the real RGAT), `.[data]` (TII-SSRC-23 loader).

=======
## Status — Phase 1 + Phase 2 implemented

| Phase | Scope | State |
|-------|-------|-------|
| 1 | ingestion → features → TB-Graph → detector → API → dashboard | ✅ |
| 2 | RGAT + anomaly model → fused threat score | ✅ (RGAT via `[ml]` extra; heuristic graph scorer otherwise) |
| 3 | explainability (feature importance, subgraph, timeline) | scaffold only |
| 4 | read-only analyst assistant | scaffold only (`POST /api/ask` → 501) |

On the built-in synthetic scenarios (8 seeds): **precision 1.0, recall 1.0, FP-rate 0.0**;
single-thread throughput ≈ **24k flows/sec**. These are the defensible numbers — see
`python -m uninet.eval.metrics`.

## Quick start

```bash
python -m pip install -e ".[dev]"        # core + pytest/ruff
python -m uninet.demo                     # synthetic traffic → alerts table + ground-truth check
python -m uninet.demo --serve             # + dashboard & API at http://127.0.0.1:8000
python -m uninet.training.train_anomaly   # fit the Isolation Forest (optional)
python -m uninet.eval.metrics             # detection metrics
python -m uninet.eval.throughput_bench --flows 200000
python -m pytest                          # 21 tests
```

Optional extras: `.[pcap]` (scapy), `.[stream]` (Kafka one-way bus),
`.[ml]` (torch + torch-geometric for the real RGAT), `.[data]` (TII-SSRC-23 loader).

Ingest a real capture: `python -m uninet.demo --pcap capture.pcap`.

>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
## Layout

```
src/uninet/
  schemas/      FlowRecord · TrafficBurst · TBGraph · Alert   (the data contracts)
  ingestion/    sources/{pcap,netflow,synthetic} → FlowRecord
  streaming/    bus (in-proc default | Kafka one-way) + windowed pipeline worker
  features/     flow/DNS/TLS/JA3/temporal extractor + behavioural fingerprint
  baseline/     adaptive per-host profile (false-positive suppression)
  tb_graph/     burst_builder → graph_builder → graph_store        ⭐ core
<<<<<<< HEAD
  detection/    rules · anomaly_model · rgat_model · sequence_model · detector (evidence fusion)
  explainability/  narrative + factors + timeline   ·   assistant/  offline read-only Q&A
=======
  detection/    rules · anomaly_model · rgat_model · detector (evidence fusion)
  explainability/ , assistant/   (Phase 3 / 4 — read-only)
>>>>>>> 11c991a836dcd892041c7cbc1d186621b44cc181
  api/          Flask endpoints + static dashboard
tests/  eval/  docs/  scripts/  notebooks/  config/
```

See `docs/architecture.md`, `docs/alert-schema.md`, `docs/readonly-guarantee.md`.

## Threat taxonomy

`benign · ddos · c2_beacon · dga · port_scan · data_exfil · botnet · unknown`
(`unknown` = anomalous but unclassified — the zero-day path).

---

## References
> UniNet - https://ieeexplore.ieee.org/abstract/document/11063437

> TB graph - https://www.sciencedirect.com/org/science/article/pii/S1546221825001316#2

> NetMamba - https://arxiv.org/abs/2405.11449v3

> Data diodes - https://institutionofelectronics.ac.uk/data-diodes-one-way-check-valves-of-network-security/

> TII-SSRC-23 Dataset - https://ieeexplore.ieee.org/document/10262330
