"""The read-only guarantee, enforced.

The ``uninet.assistant`` package (and anything it imports) must not pull in
networking, subprocess execution, or packet-crafting capability.
"""
import ast
import importlib
import pkgutil
from pathlib import Path

import uninet.assistant as assistant_pkg

FORBIDDEN = {
    "socket", "ssl", "subprocess", "requests", "httpx", "http.client",
    "urllib.request", "urllib3", "ftplib", "telnetlib", "paramiko", "asyncio",
    "scapy", "pyshark", "os.system",
}


def _module_files() -> list[Path]:
    root = Path(assistant_pkg.__file__).parent
    return sorted(root.rglob("*.py"))


def test_assistant_source_has_no_forbidden_imports():
    offenders: list[str] = []
    for path in _module_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name in FORBIDDEN or name.split(".")[0] in {f.split(".")[0] for f in FORBIDDEN}:
                    offenders.append(f"{path.name}: {name}")
    assert not offenders, f"assistant must stay read-only, found: {offenders}"


def test_assistant_transitive_imports_are_clean():
    for mod in pkgutil.walk_packages(assistant_pkg.__path__, assistant_pkg.__name__ + "."):
        importlib.import_module(mod.name)
    import sys

    leaked = sorted(m for m in FORBIDDEN if m in sys.modules and m in {"scapy", "pyshark", "paramiko", "requests", "httpx"})
    assert not leaked, f"importing the assistant pulled in: {leaked}"
