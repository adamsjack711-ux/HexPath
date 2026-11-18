"""Persistent local state shared by the scan and path commands."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


STATE_DIRECTORY_ENV = "HEXPATH_STATE_DIR"
LATEST_SCAN_FILENAME = "latest-scan.json"


def state_directory() -> Path:
    """Return the per-user Hexpath state directory."""
    override = os.environ.get(STATE_DIRECTORY_ENV)
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "HexPath"
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / "hexpath"
    return Path.home() / ".local" / "state" / "hexpath"


def latest_scan_path() -> Path:
    """Return the file used by ``hexpath path``."""
    return state_directory() / LATEST_SCAN_FILENAME


def save_latest_scan(document: dict[str, Any]) -> Path:
    """Atomically save the latest normalized scan and any embedded enrichment."""
    if not isinstance(document, dict):
        raise ValueError("latest scan must be a JSON object")
    directory = state_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = directory / LATEST_SCAN_FILENAME
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=directory,
            prefix=".latest-scan-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass
    return destination


def load_latest_scan() -> dict[str, Any]:
    """Load the latest scan or explain how to create it."""
    path = latest_scan_path()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError("no saved scan found; run a Hexpath scan before 'hexpath path'") from None
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read the latest saved scan: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("latest saved scan must contain a JSON object")
    return document
