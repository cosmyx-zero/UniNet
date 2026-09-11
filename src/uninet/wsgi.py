"""Production WSGI entry point — Gunicorn + gevent single worker.

    gunicorn "uninet.wsgi:app" \\
        --worker-class gevent \\
        --workers 1 \\
        --bind 0.0.0.0:${PORT:-8000} \\
        --timeout 120 \\
        --keep-alive 75

The gevent worker calls ``gevent.monkey.patch_all()`` before importing this
module, so all stdlib I/O (threading, socket, select) is already cooperative by
the time the pipeline runs.  One worker is intentional: ``app.config`` is
process-local, and all SSE subscribers are held as greenlets within the same
gevent hub — no shared-state issues.

Environment variables (all optional):
    UNINET_DEVICES   — simulated device count (default 8; set to 1000 on Render)
    UNINET_SEED      — synthetic-data seed (default 42)
    UNINET_INTERVAL  — live-refresh interval in seconds (default 30)
    UNINET_RETRAIN   — set to "1" to force-retrain the anomaly model on boot
"""
from __future__ import annotations

import os

from uninet.api.app import create_app, set_result
from uninet.cli import _ensure_anomaly_model, _make_source
from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.streaming.service import LiveService
from uninet.streaming.worker import run_pipeline

# ── boot config ────────────────────────────────────────────────────────────
_settings = load_settings()
_n_devices = int(os.getenv("UNINET_DEVICES", "8"))
_seed = int(os.getenv("UNINET_SEED", "42"))
_interval = float(os.getenv("UNINET_INTERVAL", "30"))
_retrain = os.getenv("UNINET_RETRAIN", "0") == "1"

# Apply CLI overrides from env vars the same way cli.py does.
if (port_env := os.getenv("PORT")):
    _settings.api_port = int(port_env)
_settings.api_host = os.getenv("UNINET_API_HOST", _settings.api_host)

# ── anomaly model ───────────────────────────────────────────────────────────
_ensure_anomaly_model(_settings, force=_retrain)

# ── initial pipeline run ────────────────────────────────────────────────────
print(f"· UniNet wsgi boot — {_n_devices} device scenario, seed {_seed} …", flush=True)
_detector = Detector.from_settings(_settings)
_result = run_pipeline(
    _make_source(None, _seed, n_devices=_n_devices),
    _settings,
    detector=_detector,
)
print(
    f"· {_result.flow_count:,} flows → {len(_result.alerts)} alerts "
    f"(graph {_result.graph.stats()['nodes']} nodes)",
    flush=True,
)

# ── Flask app ───────────────────────────────────────────────────────────────
app = create_app(_result, settings=_settings)
app.config["LIVE"] = True
app.config["DEVICE_COUNT"] = _n_devices

# ── live refresh ────────────────────────────────────────────────────────────
_counter: dict[str, int] = {"n": 0}


def _factory():
    _counter["n"] += 1
    # Rotate seeds so each refresh sees varied traffic patterns.
    return _make_source(None, _seed + _counter["n"], n_devices=_n_devices)


_live = LiveService(
    _factory, _settings, interval=_interval,
    on_update=lambda res: set_result(app, res),
)
_live.start()
print(f"· live refresh armed — every {_interval:g}s", flush=True)
