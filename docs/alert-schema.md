# Alert schema

Canonical definition: `src/uninet/schemas/alert.py` (`Alert`). Everything - API,
assistant, frontend - consumes this shape.

```jsonc
{
  "alert_id": "b1e5…",
  "created_ts": 1700000123.4,
  "window_start": 1700000000.0,
  "window_end":   1700000060.0,
  "src_host": "10.0.0.31",
  "peers": ["198.51.100.7"],
  "threat_type": "c2_beacon",          // benign|ddos|c2_beacon|dga|port_scan|data_exfil|botnet|unknown
  "confidence": 0.88,                    // fused, [0,1]
  "severity": "critical",               // low|medium|high|critical
  "title": "C2 beaconing from 10.0.0.31",
  "summary": "Host 10.0.0.31 over 60s: 18 regular check-ins to 198.51.100.7 …",
  "evidence": [
    {
      "kind": "rule",                   // rule|anomaly|ml|graph
      "name": "beacon_periodicity",
      "detail": "18 regular check-ins to 198.51.100.7 (periodicity 0.94, gap CoV 0.05)",
      "score": 0.86,
      "data": { "periodicity": 0.94, "gap_cov": 0.05 }
    }
  ],
  "graph_node_ids": ["burst:10.0.0.31->198.51.100.7#3@1700000090"],
  "scores": { "rule": 0.86, "anomaly": 0.41, "graph": 0.79 }
}
```

`GET /api/alerts` returns a list of these, sorted by `confidence` desc.
`GET /api/explain/<alert_id>` returns the same evidence re-ordered by weight with
the fusion breakdown.
