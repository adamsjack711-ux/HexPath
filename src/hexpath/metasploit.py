"""Read CVE-to-module references from an installed Metasploit Framework."""

from __future__ import annotations

from collections import defaultdict
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any


_METADATA = Path("db/modules_metadata_base.json")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def find_module_metadata(path: str | None = None) -> Path | None:
    """Find the framework's generated module metadata, or use an explicit path."""
    if path is not None:
        supplied = Path(path).expanduser()
        selected = supplied / _METADATA if supplied.is_dir() else supplied
        if not selected.is_file():
            raise ValueError(f"Metasploit module metadata not found: {selected}")
        return selected

    roots = [
        os.environ.get("MSF_ROOT"),
        os.environ.get("METASPLOIT_FRAMEWORK_ROOT"),
        "/usr/share/metasploit-framework",
        "/opt/metasploit-framework",
        "/opt/metasploit-framework/embedded/framework",
    ]
    executable = shutil.which("msfconsole")
    if executable:
        resolved = Path(executable).resolve()
        roots.extend(str(parent) for parent in resolved.parents)
    for root in roots:
        if root:
            candidate = Path(root).expanduser() / _METADATA
            if candidate.is_file():
                return candidate
    return None


def load_module_index(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Index installed Metasploit modules by their declared CVE references."""
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read Metasploit module metadata {path}: {error}") from error
    if not isinstance(metadata, dict):
        raise ValueError(f"Metasploit module metadata must be a JSON object: {path}")

    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for key, item in metadata.items():
        if not isinstance(item, dict):
            continue
        fullname = item.get("fullname") or key
        references = item.get("references")
        if not isinstance(fullname, str) or not isinstance(references, list):
            continue
        module = {
            "fullname": fullname,
            "name": item.get("name") if isinstance(item.get("name"), str) else fullname,
            "type": item.get("type") if isinstance(item.get("type"), str) else None,
            "rank": item.get("rank") if isinstance(item.get("rank"), int) else None,
        }
        for cve in {
            reference.upper() for reference in references
            if isinstance(reference, str) and _CVE.fullmatch(reference)
        }:
            index[cve].append(module)
    for modules in index.values():
        modules.sort(key=lambda module: (-(module["rank"] or 0), module["fullname"]))
    return dict(index)
