"""File-backed user and group store for multi-user auth."""
from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


class UserStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: dict = {"users": [], "groups": []}
        self._load()

    def _load(self) -> None:
        if self._path.is_file():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                pass

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    # ---- users -------------------------------------------------------

    def get_user(self, username: str) -> dict | None:
        for u in self._data["users"]:
            if u["username"] == username:
                return u
        return None

    def check_password(self, username: str, password: str) -> bool:
        u = self.get_user(username)
        if not u:
            return False
        return _hash(password, u["salt"]) == u["password_hash"]

    def get_role(self, username: str) -> str:
        u = self.get_user(username)
        return u["role"] if u else "operator"

    def list_users(self) -> list[dict]:
        return [
            {"username": u["username"], "role": u["role"], "group": u.get("group", "")}
            for u in self._data["users"]
        ]

    def add_user(self, username: str, password: str, role: str = "operator", group: str = "") -> None:
        if self.get_user(username):
            raise ValueError(f"User {username!r} already exists")
        salt = secrets.token_hex(16)
        self._data["users"].append(
            {"username": username, "password_hash": _hash(password, salt), "salt": salt, "role": role, "group": group}
        )
        self._save()

    def update_user(
        self,
        username: str,
        *,
        role: str | None = None,
        group: str | None = None,
        password: str | None = None,
    ) -> None:
        u = self.get_user(username)
        if not u:
            raise ValueError(f"User {username!r} not found")
        if role is not None:
            u["role"] = role
        if group is not None:
            u["group"] = group
        if password is not None:
            salt = secrets.token_hex(16)
            u["salt"] = salt
            u["password_hash"] = _hash(password, salt)
        self._save()

    def delete_user(self, username: str) -> None:
        self._data["users"] = [u for u in self._data["users"] if u["username"] != username]
        self._save()

    # ---- groups ------------------------------------------------------

    def list_groups(self) -> list[dict]:
        return list(self._data.get("groups", []))

    def add_group(self, name: str, description: str = "") -> None:
        if any(g["name"] == name for g in self._data.get("groups", [])):
            raise ValueError(f"Group {name!r} already exists")
        self._data.setdefault("groups", []).append({"name": name, "description": description})
        self._save()

    def delete_group(self, name: str) -> None:
        self._data["groups"] = [g for g in self._data.get("groups", []) if g["name"] != name]
        self._save()
