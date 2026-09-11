"""Admin panel — user and group management. Admin-role only."""
from __future__ import annotations

from functools import wraps

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _store():
    return current_app.config["USER_STORE"]


def _settings():
    return current_app.config["SETTINGS"]


def _is_admin() -> bool:
    user = session.get("user")
    if not user:
        return False
    if user == _settings().auth_user:
        return True
    return _store().get_role(user) == "admin"


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("auth.login", next=request.path))
        if not _is_admin():
            return jsonify(error="admin access required"), 403
        return view(*args, **kwargs)
    return wrapped


# ---- UI ----------------------------------------------------------------

@bp.get("/")
@admin_required
def panel():
    return render_template("admin.html", user=session.get("user"))


# ---- Users API ---------------------------------------------------------

@bp.get("/api/users")
@admin_required
def list_users():
    s = _settings()
    bootstrap = {"username": s.auth_user, "role": "admin", "group": "system"}
    return jsonify(users=[bootstrap] + _store().list_users())


@bp.post("/api/users")
@admin_required
def create_user():
    d = request.get_json(force=True) or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    role = d.get("role", "operator")
    group = d.get("group", "")
    if not username or not password:
        return jsonify(error="username and password required"), 400
    if role not in ("admin", "operator", "viewer"):
        return jsonify(error="invalid role — must be admin, operator, or viewer"), 400
    try:
        _store().add_user(username, password, role=role, group=group)
    except ValueError as exc:
        return jsonify(error=str(exc)), 409
    return jsonify(ok=True), 201


@bp.patch("/api/users/<username>")
@admin_required
def update_user(username: str):
    if username == _settings().auth_user:
        return jsonify(error="bootstrap account cannot be edited here"), 403
    d = request.get_json(force=True) or {}
    try:
        _store().update_user(
            username,
            role=d.get("role"),
            group=d.get("group"),
            password=d.get("password") or None,
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 404
    return jsonify(ok=True)


@bp.delete("/api/users/<username>")
@admin_required
def delete_user(username: str):
    if username == _settings().auth_user:
        return jsonify(error="bootstrap account cannot be deleted"), 403
    _store().delete_user(username)
    return jsonify(ok=True)


# ---- Groups API --------------------------------------------------------

@bp.get("/api/groups")
@admin_required
def list_groups():
    return jsonify(groups=_store().list_groups())


@bp.post("/api/groups")
@admin_required
def create_group():
    d = request.get_json(force=True) or {}
    name = (d.get("name") or "").strip()
    if not name:
        return jsonify(error="name required"), 400
    try:
        _store().add_group(name, d.get("description", ""))
    except ValueError as exc:
        return jsonify(error=str(exc)), 409
    return jsonify(ok=True), 201


@bp.delete("/api/groups/<name>")
@admin_required
def delete_group(name: str):
    _store().delete_group(name)
    return jsonify(ok=True)
