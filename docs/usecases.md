# UniNet — User Use Cases

UniNet is aimed at network defenders and security analysts who need passive, evidence-rich threat detection without instrumenting or modifying the monitored network.

---

## Personas

| Persona | Goal |
|---------|------|
| **SOC Analyst** | Triage incoming alerts quickly and understand why a host was flagged |
| **Threat Hunter** | Investigate host behaviour patterns and lateral movement across windows |
| **ML/Security Engineer** | Train, evaluate, and tune detection models on captured traffic |
| **DevOps / Platform Engineer** | Deploy UniNet as a sidecar or isolated sensor and integrate alerts into SIEM |

---

## Use Case 1 — Investigate a C2 Beaconing Alert

**Trigger:** The dashboard shows a HIGH alert: "C2 beaconing from 10.0.1.42".

**Steps:**
1. Open the alert detail. The **Evidence** tab shows:
   - Rule signal: `c2_beacon` — beacon interval 60 s ± 2 s, 8 consecutive bursts.
   - Graph signal: TB-Graph subgraph has a strong `periodic` edge chain.
   - Confidence: 0.83 (HIGH → CRITICAL once the corroboration bonus fires).
2. Click **Ask** → type *"why is this flagged as C2?"*
   - Assistant (intent: `why`) returns the narrative + top signals from the explanation.
3. Ask *"who is it talking to?"* (intent: `peers`) — returns the external IPs / SNIs.
4. Ask *"what should I do next?"* (intent: `next`) — returns read-only investigation steps:
   - Pull the PCAP slice for the window and confirm the check-in interval.
   - Look up destination IP/SNI reputation out-of-band.
   - Check whether other hosts share this behavioural fingerprint.
5. Analyst hands off the PCAP slice and IP list to a threat-intel workflow. UniNet itself takes no action.

---

## Use Case 2 — Hunt for DGA Activity

**Trigger:** Threat hunter notices a spike in NXDOMAIN-heavy hosts on the dashboard.

**Steps:**
1. Filter `/api/alerts?threat_type=dga` to get the affected hosts and time windows.
2. For each alert use `/api/explain/<alert_id>` to get the **burst timeline** — it lists the DNS resolution bursts and the domains queried.
3. Ask the assistant *"show me the timeline"* (intent: `timeline`) for a per-burst sequence.
4. Export domain lists from the explanation's `key_factors` and feed into a DGA classifier or threat-intel feed (outside UniNet).
5. Tune `threat_rules.yaml` (`dga_nxdomain_rate_threshold`) if the false-positive rate is too high.

---

## Use Case 3 — Detect a Port Scan / Reconnaissance

**Trigger:** Automated alert at LOW severity: "Port scan / reconnaissance from 192.168.10.5".

**Steps:**
1. Check the `scores` field: high `rule` score, low `anomaly` — the host is known but broke a rate rule.
2. Ask *"which ports were scanned?"* — the assistant surfaces the `key_factors` (unique port count, SYN-only ratio).
3. Ask *"is this authorised?"* via the `next` intent — reminder to cross-check against authorised scanner inventory.
4. Analyst marks the source as a sanctioned asset (in their SIEM / CMDB, not in UniNet); future windows from that host will still be scored but context is managed externally.

---

## Use Case 4 — Zero-Day / Unknown Anomaly

**Trigger:** Alert with `threat_type = UNKNOWN` — anomaly model fired (score 0.87) but no rule or graph hint matched a known class.

**Steps:**
1. Ask *"how confident are you?"* (intent: `confidence`) — analyst sees that the 0.87 anomaly score dominates; rules and graph contributed low scores.
2. Ask *"explain"* / *"why"* — narrative calls out the deviating features (e.g. byte-count distribution, unusual burst interval).
3. Analyst saves the evidence bundle (`/api/explain/<id>`) for later signature authoring once the class is identified.
4. After external investigation confirms the class, a new rule can be added to `threat_rules.yaml`.

---

## Use Case 5 — Continuous Live Monitoring

**Trigger:** Platform engineer deploys UniNet alongside a passive tap in a production segment.

**Setup:**
```bash
python -m uninet --live --interval 60 --workers 4 --source netflow://0.0.0.0:2055
```

**How it works:**
- `LiveService` re-runs the sharded pipeline every 60 s.
- New alerts appear on the dashboard in near-real-time via `/api/stream` (Server-Sent Events).
- SIEM integration: poll `/api/alerts?since=<epoch>` on the same interval and ingest `Alert` JSON.
- No agent is installed on monitored hosts; no traffic is emitted by UniNet.

---

## Use Case 6 — Model Training and Evaluation

**Trigger:** ML engineer wants to retrain the Isolation Forest on new baseline traffic.

**Steps:**
1. Collect clean (benign) PCAP data, run `scripts/prepare_data.py` to produce feature vectors.
2. Train: `python -m uninet.training.train_anomaly --data data/processed/features.npz --out models/anomaly.pkl`
3. Evaluate: `python -m uninet.eval.metrics` — precision / recall / F1 against labelled PCAP.
4. Update `config/config.yaml` → `model_path_anomaly` to point at the new checkpoint.
5. The R-GAT model follows the same pattern via `train_rgat.py`; GRU sequence model via `train_sequence.py`.

---

## Connecting to the API

All use cases above can be driven programmatically. Base URL defaults to `http://localhost:5000`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | List alerts; filter by `?threat_type=` `?since=` `?host=` |
| `/api/alerts/<id>` | GET | Single alert JSON |
| `/api/explain/<id>` | GET | Full explanation (narrative, signals, timeline, fusion bars) |
| `/api/graph` | GET | Live TB-Graph (nodes + edges) |
| `/api/ask` | POST | Assistant Q&A — body: `{"alert_id": "...", "question": "..."}` |
| `/api/stream` | GET (SSE) | Push new alerts as they are detected |

**Quick test:**
```bash
# run a PCAP and ask about the first alert
ALERT_ID=$(curl -s http://localhost:5000/api/alerts | python -c "import sys,json; print(json.load(sys.stdin)[0]['alert_id'])")
curl -s -X POST http://localhost:5000/api/ask \
  -H "Content-Type: application/json" \
  -d "{\"alert_id\": \"$ALERT_ID\", \"question\": \"why is this flagged?\"}"
```

---

## What UniNet Does NOT Do

- It does not block traffic, reset connections, or send any packet.
- The assistant is offline and templated — it does not call an LLM or external service.
- It does not store raw packet payloads — only flow-level metadata and derived features.
- It does not authenticate or authorise users on its own — deploy behind a reverse proxy with auth if the dashboard is externally accessible.
