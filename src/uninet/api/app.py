"""Flask API + dashboard.

Endpoints (all GET unless noted, all read-only):
    /                     dashboard
    /api/health
    /api/stats            flow / window / graph / alert counts
    /api/alerts           list of Alert JSON
    /api/alerts/<id>      one Alert
    /api/explain/<id>     evidence breakdown for one Alert
    /api/graph?host=IP    TB-Graph view (subgraph for a host, or whole graph)
    /api/ask   (POST)     reserved for the Phase 4 read-only assistant -> 501
"""
from __future__ import annotations

import webbrowser
from threading import Timer

from flask import Flask, jsonify, render_template, request

from uninet.config import Settings, load_settings
from uninet.streaming.worker import PipelineResult, run_pipeline


def create_app(result: PipelineResult | None = None, settings: Settings | None = None) -> Flask:
    settings = settings or load_settings()
    app = Flask(__name__, template_folder="templates", static_folder="static")

    if result is None:
        from uninet.ingestion.sources.synthetic import SyntheticSource

        result = run_pipeline(SyntheticSource(), settings)

    app.config["RESULT"] = result
    app.config["SETTINGS"] = settings
    alerts_by_id = {a.alert_id: a for a in result.alerts}

    # ---- UI ------------------------------------------------------- #
    @app.get("/")
    def index():
        return render_template("index.html")

    # ---- API ------------------------------------------------------ #
    @app.get("/api/health")
    def health():
        return jsonify(status="ok", mode="read-only")

    @app.get("/api/stats")
    def stats():
        r: PipelineResult = app.config["RESULT"]
        by_sev: dict[str, int] = {}
        for a in r.alerts:
            by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1
        return jsonify(
            flows=r.flow_count,
            windows=r.window_count,
            graph=r.graph.stats(),
            alerts=len(r.alerts),
            by_severity=by_sev,
        )

    @app.get("/api/alerts")
    def alerts():
        r: PipelineResult = app.config["RESULT"]
        return jsonify([a.model_dump(mode="json") for a in
                        sorted(r.alerts, key=lambda x: -x.confidence)])

    @app.get("/api/alerts/<alert_id>")
    def alert_one(alert_id: str):
        a = alerts_by_id.get(alert_id)
        return (jsonify(a.model_dump(mode="json")) if a else (jsonify(error="not found"), 404))

    @app.get("/api/explain/<alert_id>")
    def explain(alert_id: str):
        a = alerts_by_id.get(alert_id)
        if not a:
            return jsonify(error="not found"), 404
        return jsonify(
            alert_id=a.alert_id,
            threat_type=a.threat_type.value,
            confidence=a.confidence,
            fused_from=a.scores,
            evidence=[e.model_dump(mode="json") for e in a.evidence],
            graph_anchors=a.graph_node_ids,
        )

    @app.get("/api/graph")
    def graph():
        r: PipelineResult = app.config["RESULT"]
        host = request.args.get("host")
        if host:
            view = r.graph.to_view(r.graph.subgraph_for_host(host))
        else:
            view = r.graph.to_view()
        return jsonify(view.model_dump(mode="json"))

    @app.post("/api/ask")
    def ask():
        return jsonify(
            error="read-only analyst assistant is Phase 4",
            allowed=["read alerts", "read evidence", "read TB-Graph"],
            never=["network", "shell", "firewall", "packet injection", "autonomous response"],
        ), 501

    return app


def serve(app: Flask, settings: Settings | None = None, open_browser: bool = True) -> None:
    settings = settings or load_settings()
    url = f"http://{settings.api_host}:{settings.api_port}/"
    if open_browser:
        Timer(0.8, lambda: webbrowser.open(url)).start()
    print(f"  UniNet dashboard  ->  {url}   (Ctrl+C to stop)")
    app.run(host=settings.api_host, port=settings.api_port, debug=False)


if __name__ == "__main__":
    serve(create_app())
