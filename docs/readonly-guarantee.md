# Read-only / unidirectional guarantee

UniNet is a **passive** monitor. It sits behind a one-way tap or data diode and
never originates traffic toward the monitored network.

## What the system may do
- Read PCAP / NetFlow / IPFIX / sFlow exports and message-bus records.
- Compute features, build the TB-Graph, run models, raise alerts.
- Serve alerts, evidence and the TB-Graph over a read-only HTTP API + dashboard.

## What the system must never do
- Send packets, probe, scan, or complete handshakes.
- Decrypt payloads (TLS/QUIC is analysed by **metadata only** — SNI, JA3/JA3S/JA4).
- Issue mitigation / firewall / blocking commands.
- Give the analyst assistant any capability beyond reading detection artifacts.

## How it is enforced
- `tests/test_assistant_readonly.py` fails the build if the `assistant` package
  (transitively) imports `socket`, `ssl`, `subprocess`, `requests`, `httpx`,
  `urllib.request`, `scapy`, `ftplib`, `telnetlib`, `paramiko`.
- The Flask app defines no mutating routes. `POST /api/ask` is `501` until the
  Phase 4 assistant ships, and that assistant is read-only by construction.
- Ingestion sources are file / bus consumers only; `pcap.py` deliberately omits
  live capture.
