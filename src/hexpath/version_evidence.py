"""Import scoped, protocol-specific version evidence into a saved scan."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

from hexpath.assessment import validate_scans
from hexpath.scope import Scope
from hexpath.vulnerabilities import CpeIdentity, VulnerabilityError


_RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def read_zgrab2_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read complete ZGrab2 JSONL records, retaining their source line."""
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"ZGrab2 line {line_number} is invalid JSON: {error.msg}") from error
        if not isinstance(row, dict):
            raise ValueError(f"ZGrab2 line {line_number} must be an object")
        rows.append(row)
    if not rows:
        raise ValueError("ZGrab2 input has no records")
    return rows


def confirm_mongodb_build_info(
    scope: Scope, scan_document: object, rows: list[dict[str, Any]], *, reference: str,
) -> dict[str, Any]:
    """Copy a scan and confirm only matching MongoDB services from buildInfo."""
    scan = validate_scans(scope, [scan_document])[0]
    if not rows:
        raise ValueError("ZGrab2 input has no records")
    seen: set[tuple[str, int]] = set()
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"ZGrab2 record {number} must be an object")
        address = scope.require_authorized(row.get("ip"))
        if address.version != 6 or row.get("ip") != str(address):
            raise ValueError(f"ZGrab2 record {number} requires a canonical IPv6 address")
        module = row.get("data", {}).get("mongodb") if isinstance(row.get("data"), dict) else None
        if not isinstance(module, dict) or module.get("status") != "success" or module.get("protocol") != "mongodb":
            raise ValueError(f"ZGrab2 record {number} is not a successful MongoDB probe")
        port = module.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"ZGrab2 record {number} has an invalid port")
        timestamp = module.get("timestamp")
        try:
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise ValueError(f"ZGrab2 record {number} has an invalid timestamp") from error
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise ValueError(f"ZGrab2 record {number} needs a timezone-aware timestamp")
        result = module.get("result")
        build_info = result.get("build_info") if isinstance(result, dict) else None
        version = build_info.get("version") if isinstance(build_info, dict) else None
        if not isinstance(version, str) or _RELEASE.fullmatch(version) is None:
            raise ValueError(f"ZGrab2 record {number} has no exact buildInfo.version")
        key = (str(address), port)
        if key in seen:
            raise ValueError(f"ZGrab2 input repeats MongoDB service [{address}]:{port}")
        seen.add(key)
        matching = [
            service for service in scan["services"]
            if service.get("host") == str(address) and service.get("port") == port
            and service.get("protocol") == "tcp" and service.get("state") == "open"
        ]
        if len(matching) != 1:
            raise ValueError(f"ZGrab2 record {number} has no unique open TCP service in the scan")
        service = matching[0]
        if service.get("id") != f"service:[{address}]:tcp:{port}":
            raise ValueError(f"scan service [{address}]:{port} has an inconsistent id")
        labels = [str(service.get(field) or "").strip().lower() for field in ("name", "product")]
        if not any(label == "mongodb" or label.startswith("mongodb ") for label in labels):
            raise ValueError(f"scan service [{address}]:{port} is not identified as MongoDB")
        if "version_confirmation" in service:
            raise ValueError(f"scan service [{address}]:{port} already has version confirmation")
        for raw_cpe in service.get("cpes", []):
            try:
                identity = CpeIdentity(raw_cpe)
            except VulnerabilityError as error:
                raise ValueError(f"scan service [{address}]:{port} has an invalid CPE") from error
            fields = identity.value.split(":")
            if fields[2:5] != ["a", "mongodb", "mongodb"]:
                raise ValueError(f"scan service [{address}]:{port} has a non-MongoDB CPE")
            if identity.precise_version and fields[5] != version:
                raise ValueError(f"scan service [{address}]:{port} has a conflicting precise CPE")
        original = {name: service.get(name) for name in ("name", "product", "version", "cpes")}
        service["original_identity"] = original
        service["version"] = version
        service["cpes"] = [f"cpe:/a:mongodb:mongodb:{version}"]
        service["version_confirmation"] = {
            "source": "zgrab2 mongodb buildInfo", "version": version,
            "collected_at": parsed_time.isoformat(), "reference": f"{reference}#record-{number}",
        }
        evidence = service.setdefault("evidence", [])
        if not isinstance(evidence, list):
            raise ValueError(f"scan service [{address}]:{port} has invalid evidence")
        evidence.append({
            "source": "zgrab2 mongodb buildInfo", "level": "observed",
            "summary": f"MongoDB buildInfo.version reported {version}",
            "collected_at": parsed_time.isoformat(), "reference": f"{reference}#record-{number}",
        })
    return scan
