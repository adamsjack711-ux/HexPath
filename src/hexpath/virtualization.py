"""Read-only libvirt inventory for complete hypervisor topology output."""

from __future__ import annotations

from collections.abc import Callable
import json
import re
import subprocess
from typing import Any
from xml.etree import ElementTree


class VirtualizationError(RuntimeError):
    """Raised when libvirt inventory cannot be collected or parsed."""


CommandRunner = Callable[[tuple[str, ...], int], str]
_SAFE_REMOTE_VALUE = re.compile(r"^[A-Za-z0-9_.@:-]+$")


def collect_libvirt_inventory(
    *,
    ssh_host: str | None = None,
    timeout_seconds: int = 20,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Collect domains and virtual networks locally or through SSH."""
    if timeout_seconds <= 0:
        raise VirtualizationError("timeout_seconds must be greater than zero")
    if ssh_host is not None:
        _validate_remote_value(ssh_host, "SSH host")
        prefix = ("ssh", "--", ssh_host)
    else:
        prefix = ()
    execute = runner or _run_command

    def run(*arguments: str) -> str:
        return execute(prefix + tuple(arguments), timeout_seconds)

    server = run("hostname").strip()
    if not server:
        raise VirtualizationError("inventory host returned an empty hostname")

    domain_names = _nonempty_lines(run("virsh", "list", "--all", "--name"))
    domains = tuple(_read_domain(run, name) for name in domain_names)

    network_names = _nonempty_lines(run("virsh", "net-list", "--all", "--name"))
    active_networks = set(
        _nonempty_lines(run("virsh", "net-list", "--name"))
    )
    networks = tuple(
        _read_network(run, name, active=name in active_networks)
        for name in network_names
    )

    return {
        "source": "libvirt",
        "server": server,
        "connection": ssh_host or "local",
        "networks": list(networks),
        "vms": list(domains),
    }


def collect_server_inventory(
    *,
    ssh_host: str | None = None,
    timeout_seconds: int = 20,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Collect system, network, service, VM, and container inventory."""
    inventory = collect_libvirt_inventory(
        ssh_host=ssh_host,
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    prefix = ("ssh", "--", ssh_host) if ssh_host is not None else ()
    execute = runner or _run_command

    def run(*arguments: str) -> str:
        return execute(prefix + tuple(arguments), timeout_seconds)

    os_release = _parse_os_release(run("cat", "/etc/os-release"))
    inventory["source"] = "server-inventory"
    inventory["system"] = {
        "os": os_release.get("PRETTY_NAME", os_release.get("NAME", "unknown")),
        "kernel": run("uname", "-srmo").strip(),
    }
    inventory["interfaces"] = _parse_interfaces(run("ip", "-j", "address", "show"))
    inventory["listening_services"] = _parse_listening_services(
        run("ss", "-H", "-lntup")
    )
    inventory["containers"] = _read_containers(run)
    inventory["container_networks"] = _read_container_networks(run)
    return inventory


def _read_domain(run: Callable[..., str], name: str) -> dict[str, Any]:
    _validate_remote_value(name, "domain name")
    root = _parse_xml(run("virsh", "dumpxml", name), f"domain {name!r}")
    state = run("virsh", "domstate", name).strip()
    interfaces: list[dict[str, str | None]] = []
    for interface in root.findall("./devices/interface"):
        source = interface.find("source")
        model = interface.find("model")
        mac = interface.find("mac")
        interfaces.append(
            {
                "type": interface.attrib.get("type"),
                "network": source.attrib.get("network") if source is not None else None,
                "bridge": source.attrib.get("bridge") if source is not None else None,
                "model": model.attrib.get("type") if model is not None else None,
                "mac": mac.attrib.get("address") if mac is not None else None,
            }
        )
    memory = root.find("memory")
    vcpu = root.find("vcpu")
    return {
        "name": name,
        "uuid": _optional_element_text(root, "uuid"),
        "state": state,
        "memory": int(memory.text) if memory is not None and memory.text else None,
        "memory_unit": memory.attrib.get("unit") if memory is not None else None,
        "vcpus": int(vcpu.text) if vcpu is not None and vcpu.text else None,
        "interfaces": interfaces,
    }


def _read_network(
    run: Callable[..., str],
    name: str,
    *,
    active: bool,
) -> dict[str, Any]:
    _validate_remote_value(name, "network name")
    root = _parse_xml(run("virsh", "net-dumpxml", name), f"network {name!r}")
    bridge = root.find("bridge")
    return {
        "name": name,
        "uuid": _optional_element_text(root, "uuid"),
        "active": active,
        "bridge": bridge.attrib.get("name") if bridge is not None else None,
    }


def _read_containers(run: Callable[..., str]) -> list[dict[str, Any]]:
    identifiers = _nonempty_lines(run("docker", "ps", "-aq", "--no-trunc"))
    if not identifiers:
        return []
    for identifier in identifiers:
        _validate_docker_id(identifier)
    documents = _parse_json(
        run("docker", "inspect", *identifiers),
        "Docker container inventory",
    )
    if not isinstance(documents, list):
        raise VirtualizationError("Docker inspect did not return a list")
    containers: list[dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict):
            raise VirtualizationError("Docker inspect returned an invalid container")
        network_settings = document.get("NetworkSettings") or {}
        raw_networks = network_settings.get("Networks") or {}
        networks = [
            {
                "name": name,
                "ipv4": details.get("IPAddress") or None,
                "ipv6": details.get("GlobalIPv6Address") or None,
                "mac": details.get("MacAddress") or None,
            }
            for name, details in raw_networks.items()
            if isinstance(name, str) and isinstance(details, dict)
        ]
        raw_ports = network_settings.get("Ports") or {}
        ports: list[dict[str, Any]] = []
        for container_port, bindings in raw_ports.items():
            if bindings is None:
                ports.append({"container": container_port, "host": None})
                continue
            if not isinstance(bindings, list):
                continue
            for binding in bindings:
                if isinstance(binding, dict):
                    host_ip = binding.get("HostIp", "")
                    host_port = binding.get("HostPort", "")
                    ports.append(
                        {
                            "container": container_port,
                            "host": f"{host_ip}:{host_port}" if host_port else None,
                        }
                    )
        config = document.get("Config") or {}
        state = document.get("State") or {}
        identifier = str(document.get("Id", ""))
        containers.append(
            {
                "id": identifier[:12],
                "name": str(document.get("Name", "")).removeprefix("/"),
                "image": config.get("Image"),
                "state": state.get("Status"),
                "networks": networks,
                "ports": ports,
            }
        )
    return containers


def _read_container_networks(run: Callable[..., str]) -> list[dict[str, Any]]:
    identifiers = _nonempty_lines(run("docker", "network", "ls", "-q", "--no-trunc"))
    if not identifiers:
        return []
    for identifier in identifiers:
        _validate_docker_id(identifier)
    documents = _parse_json(
        run("docker", "network", "inspect", *identifiers),
        "Docker network inventory",
    )
    if not isinstance(documents, list):
        raise VirtualizationError("Docker network inspect did not return a list")
    networks: list[dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict):
            raise VirtualizationError("Docker returned an invalid network")
        ipam = document.get("IPAM") or {}
        configurations = ipam.get("Config") or []
        networks.append(
            {
                "id": str(document.get("Id", ""))[:12],
                "name": document.get("Name"),
                "driver": document.get("Driver"),
                "scope": document.get("Scope"),
                "internal": bool(document.get("Internal", False)),
                "ipv6": bool(document.get("EnableIPv6", False)),
                "subnets": [
                    config.get("Subnet")
                    for config in configurations
                    if isinstance(config, dict) and config.get("Subnet")
                ],
            }
        )
    return networks


def _parse_interfaces(value: str) -> list[dict[str, Any]]:
    documents = _parse_json(value, "interface inventory")
    if not isinstance(documents, list):
        raise VirtualizationError("interface inventory must be a list")
    interfaces: list[dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict) or not isinstance(
            document.get("ifname"), str
        ):
            raise VirtualizationError("interface inventory contains an invalid record")
        addresses = [
            {
                "family": address.get("family"),
                "address": address.get("local"),
                "prefixlen": address.get("prefixlen"),
                "scope": address.get("scope"),
            }
            for address in document.get("addr_info", [])
            if isinstance(address, dict)
        ]
        interfaces.append(
            {
                "name": document["ifname"],
                "state": document.get("operstate"),
                "kind": document.get("link_type"),
                "master": document.get("master"),
                "mac": document.get("address"),
                "addresses": addresses,
            }
        )
    return interfaces


def _parse_listening_services(value: str) -> list[dict[str, str | None]]:
    services: list[dict[str, str | None]] = []
    for line in value.splitlines():
        fields = line.split(maxsplit=6)
        if len(fields) < 6:
            continue
        services.append(
            {
                "protocol": fields[0],
                "state": fields[1],
                "local": fields[4],
                "peer": fields[5],
                "process": fields[6] if len(fields) == 7 else None,
            }
        )
    return services


def _parse_os_release(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in value.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, raw_value = line.split("=", 1)
        result[key] = raw_value.strip().strip('"')
    return result


def _parse_json(value: str, record_name: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as error:
        raise VirtualizationError(f"invalid {record_name} JSON: {error}") from error


def _validate_docker_id(value: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{12,64}", value):
        raise VirtualizationError(f"invalid Docker identifier: {value!r}")


def _run_command(arguments: tuple[str, ...], timeout_seconds: int) -> str:
    try:
        process = subprocess.run(
            arguments,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise VirtualizationError(
            f"inventory command exceeded {timeout_seconds} seconds"
        ) from error
    except OSError as error:
        raise VirtualizationError(f"could not run inventory command: {error}") from error
    if process.returncode != 0:
        message = process.stderr.strip() or "inventory command failed"
        raise VirtualizationError(message)
    return process.stdout


def _parse_xml(value: str, record_name: str) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(value)
    except ElementTree.ParseError as error:
        raise VirtualizationError(f"invalid {record_name} XML: {error}") from error


def _optional_element_text(root: ElementTree.Element, name: str) -> str | None:
    element = root.find(name)
    return element.text.strip() if element is not None and element.text else None


def _nonempty_lines(value: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def _validate_remote_value(value: str, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or not _SAFE_REMOTE_VALUE.fullmatch(value)
    ):
        raise VirtualizationError(f"invalid {field_name}: {value!r}")
