"""Flask backend + static dashboard. Read-only: it serves detections, never acts."""
from uninet.api.app import create_app, serve

__all__ = ["create_app", "serve"]
