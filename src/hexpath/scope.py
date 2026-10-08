"""Authorized IPv6 target scope loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address, IPv6Network, ip_address, ip_network
import json
from pathlib import Path
from typing import Any


DEFAULT_MINIMUM_PREFIX_LENGTH = 48


class ScopeError(ValueError):
    """Raised when a scope file is missing or invalid."""


class TargetOutsideScopeError(ScopeError):
    """Raised when a requested target is not in the authorized scope."""


def _reject_unsafe_network(
    network: IPv6Network,
    raw_target: str,
    minimum_prefix_length: int,
) -> None:
    """Reject scope networks that are too broad or never valid scan targets.

    The scope file is HexPath's only guard against scanning the wrong network,
    so a single mistyped prefix must not silently authorize a huge range or a
    special-use range. Breadth is bounded by ``minimum_prefix_length`` and the
    special-use categories below are always refused.
    """
    if network.prefixlen < minimum_prefix_length:
        raise ScopeError(
            f"scope target {raw_target!r} is too broad: /{network.prefixlen} "
            f"covers {network.num_addresses} addresses; the widest allowed is "
            f"/{minimum_prefix_length}. Narrow the scope to the hosts or subnet "
            f"you are authorized to test."
        )

    address = network.network_address
    if network.is_multicast:
        category = "a multicast range"
    elif network.is_loopback:
        category = "the loopback address"
    elif network.is_unspecified:
        category = "the unspecified address"
    elif network.is_link_local:
        category = "a link-local range"
    elif address.ipv4_mapped is not None:
        category = "an IPv4-mapped range (HexPath assesses IPv6 only)"
    else:
        return
    raise ScopeError(
        f"scope target {raw_target!r} is {category} and cannot be a scan target"
    )


@dataclass(frozen=True, slots=True)
class Scope:
    """A named collection of explicitly authorized IPv6 networks."""

    name: str
    networks: tuple[IPv6Network, ...]

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        minimum_prefix_length: int = DEFAULT_MINIMUM_PREFIX_LENGTH,
    ) -> Scope:
        """Create a scope from decoded JSON data."""
        if (
            isinstance(minimum_prefix_length, bool)
            or not isinstance(minimum_prefix_length, int)
            or not 0 <= minimum_prefix_length <= 128
        ):
            raise ScopeError("minimum_prefix_length must be an integer between 0 and 128")

        name = data.get("name")
        targets = data.get("targets")

        if not isinstance(name, str) or not name.strip():
            raise ScopeError("scope 'name' must be a non-empty string")
        if not isinstance(targets, list) or not targets:
            raise ScopeError("scope 'targets' must be a non-empty list")

        networks: list[IPv6Network] = []
        for raw_target in targets:
            if not isinstance(raw_target, str):
                raise ScopeError("every scope target must be a string")

            try:
                network = ip_network(raw_target, strict=True)
            except ValueError as error:
                raise ScopeError(f"invalid scope target {raw_target!r}: {error}") from error

            if not isinstance(network, IPv6Network):
                raise ScopeError(f"IPv4 target {raw_target!r} is not supported")

            _reject_unsafe_network(network, raw_target, minimum_prefix_length)
            networks.append(network)

        return cls(name=name.strip(), networks=tuple(networks))

    @classmethod
    def from_json_file(
        cls,
        path: str | Path,
        *,
        minimum_prefix_length: int = DEFAULT_MINIMUM_PREFIX_LENGTH,
    ) -> Scope:
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

        return cls.from_dict(data, minimum_prefix_length=minimum_prefix_length)

    def require_authorized(self, target: str) -> IPv6Address:
        """Return a parsed target or raise if it is invalid or unauthorized."""
        try:
            address = ip_address(target)
        except ValueError as error:
            raise ScopeError(f"invalid IP address {target!r}") from error

        if not isinstance(address, IPv6Address):
            raise ScopeError(f"IPv4 target {target!r} is not supported")

        if not any(address in network for network in self.networks):
            raise TargetOutsideScopeError(
                f"target {address} is outside authorized scope {self.name!r}"
            )

        return address

    def require_authorized_network(self, target: str) -> IPv6Network:
        """Return an IPv6 target network if it is contained by the scope."""
        try:
            network = ip_network(target, strict=True)
        except ValueError as error:
            raise ScopeError(f"invalid target network {target!r}: {error}") from error

        if not isinstance(network, IPv6Network):
            raise ScopeError(f"IPv4 target {target!r} is not supported")

        if not any(network.subnet_of(allowed) for allowed in self.networks):
            raise TargetOutsideScopeError(
                f"target {network} is outside authorized scope {self.name!r}"
            )

        return network
