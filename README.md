# UniNet
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

SIH26145 · Team Cosmyx Zero · Theme: Blockchain & Cybersecurity

Passive, unidirectional, read-only threat detection: behavioural fingerprinting →
**Traffic-Burst Graph** → hybrid AI engine (rules + anomaly + RGAT) → evidence-backed
alerts. No return path, no probing, no payload decryption.

---

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

## Layout

```
src/uninet/
  schemas/      FlowRecord · TrafficBurst · TBGraph · Alert   (the data contracts)
  ingestion/    sources/{pcap,netflow,synthetic} → FlowRecord
  streaming/    bus (in-proc default | Kafka one-way) + windowed pipeline worker
  features/     flow/DNS/TLS/JA3/temporal extractor + behavioural fingerprint
  baseline/     adaptive per-host profile (false-positive suppression)
  tb_graph/     burst_builder → graph_builder → graph_store        ⭐ core
  detection/    rules · anomaly_model · rgat_model · detector (evidence fusion)
  explainability/ , assistant/   (Phase 3 / 4 — read-only)
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
