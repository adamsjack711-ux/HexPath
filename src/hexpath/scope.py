"""Authorized IPv4 and IPv6 target scope loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
import json
from pathlib import Path
from typing import Any


class ScopeError(ValueError):
    """Raised when a scope file is missing or invalid."""


class TargetOutsideScopeError(ScopeError):
    """Raised when a requested target is not in the authorized scope."""


IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


@dataclass(frozen=True, slots=True)
class Scope:
    """A named collection of explicitly authorized IP networks."""

    name: str
    networks: tuple[IPNetwork, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scope:
        """Create a scope from decoded JSON data."""
        name = data.get("name")
        targets = data.get("targets")

        if not isinstance(name, str) or not name.strip():
            raise ScopeError("scope 'name' must be a non-empty string")
        if not isinstance(targets, list) or not targets:
            raise ScopeError("scope 'targets' must be a non-empty list")

        networks: list[IPNetwork] = []
        for raw_target in targets:
            if not isinstance(raw_target, str):
                raise ScopeError("every scope target must be a string")

            try:
                network = ip_network(raw_target, strict=True)
            except ValueError as error:
                raise ScopeError(f"invalid scope target {raw_target!r}: {error}") from error

            networks.append(network)

        return cls(name=name.strip(), networks=tuple(networks))

    @classmethod
    def from_json_file(cls, path: str | Path) -> Scope:
        """Load and validate a scope from a JSON file."""
        scope_path = Path(path)
        try:
            data = json.loads(scope_path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise ScopeError(f"scope file not found: {scope_path}") from error
        except json.JSONDecodeError as error:
            raise ScopeError(
                f"scope file contains invalid JSON at line {error.lineno}, column {error.colno}"
            ) from error

        if not isinstance(data, dict):
            raise ScopeError("scope file must contain a JSON object")

        return cls.from_dict(data)

    def require_authorized(self, target: str) -> IPAddress:
        """Return a parsed target or raise if it is invalid or unauthorized."""
        try:
            address = ip_address(target)
        except ValueError as error:
            raise ScopeError(f"invalid IP address {target!r}") from error

        if not any(
            address.version == network.version and address in network
            for network in self.networks
        ):
            raise TargetOutsideScopeError(
                f"target {address} is outside authorized scope {self.name!r}"
            )

        return address

    def require_authorized_network(self, target: str) -> IPNetwork:
        """Return an IP target network if it is contained by the scope."""
        try:
            network = ip_network(target, strict=True)
        except ValueError as error:
            raise ScopeError(f"invalid target network {target!r}: {error}") from error

        if not any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in self.networks
        ):
            raise TargetOutsideScopeError(
                f"target {network} is outside authorized scope {self.name!r}"
            )

        return network
