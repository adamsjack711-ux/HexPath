"""Tests for complete local and remote server inventory collection."""

from __future__ import annotations

import json
import unittest

from hexpath.virtualization import (
    VirtualizationError,
    collect_server_inventory,
)


class ServerInventoryTests(unittest.TestCase):
    def test_collects_running_and_stopped_virtualization_resources(self) -> None:
        container_id = "a" * 64
        network_id = "b" * 64
        responses = {
            ("hostname",): "aiserver\n",
            ("virsh", "list", "--all", "--name"): "lab-running\nlab-stopped\n",
            ("virsh", "list", "--name"): "lab-running\n",
            ("virsh", "net-list", "--all", "--name"): "security-lab\n",
            ("virsh", "net-list", "--name"): "security-lab\n",
            ("virsh", "domstate", "lab-running"): "running\n",
            ("virsh", "domstate", "lab-stopped"): "shut off\n",
            ("virsh", "dumpxml", "lab-running"): _domain_xml(
                "lab-running", "security-lab", "52:54:00:00:00:01"
            ),
            ("virsh", "dumpxml", "lab-stopped"): _domain_xml(
                "lab-stopped", "security-lab", "52:54:00:00:00:02"
            ),
            ("virsh", "net-dumpxml", "security-lab"): (
                "<network><uuid>net-1</uuid><bridge name='virbr-lab'/></network>"
            ),
            ("cat", "/etc/os-release"): 'PRETTY_NAME="Ubuntu Test"\n',
            ("uname", "-srmo"): "Linux 7.0 x86_64 GNU/Linux\n",
            ("ip", "-j", "address", "show"): json.dumps(
                [
                    {
                        "ifname": "enp3s0",
                        "operstate": "UP",
                        "link_type": "ether",
                        "address": "00:11:22:33:44:55",
                        "addr_info": [
                            {
                                "family": "inet6",
                                "local": "2001:db8::10",
                                "prefixlen": 64,
                                "scope": "global",
                            }
                        ],
                    }
                ]
            ),
            ("ss", "-H", "-lntup"): (
                'tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1,fd=3))\n'
            ),
            ("docker", "ps", "-aq", "--no-trunc"): f"{container_id}\n",
            ("docker", "inspect", container_id): json.dumps(
                [
                    {
                        "Id": container_id,
                        "Name": "/webgoat",
                        "Config": {"Image": "webgoat/webgoat"},
                        "State": {"Status": "exited"},
                        "NetworkSettings": {
                            "Networks": {
                                "pentest-lab": {
                                    "IPAddress": "172.20.0.5",
                                    "GlobalIPv6Address": "",
                                    "MacAddress": "02:42:ac:14:00:05",
                                }
                            },
                            "Ports": {"8080/tcp": None},
                        },
                    }
                ]
            ),
            ("docker", "network", "ls", "-q", "--no-trunc"): f"{network_id}\n",
            ("docker", "network", "inspect", network_id): json.dumps(
                [
                    {
                        "Id": network_id,
                        "Name": "pentest-lab",
                        "Driver": "bridge",
                        "Scope": "local",
                        "Internal": False,
                        "EnableIPv6": True,
                        "IPAM": {"Config": [{"Subnet": "fd00:20::/64"}]},
                    }
                ]
            ),
        }
        seen: list[tuple[str, ...]] = []

        def runner(arguments: tuple[str, ...], timeout: int) -> str:
            self.assertEqual(timeout, 15)
            seen.append(arguments)
            remote_command = arguments[3:]
            return responses[remote_command]

        inventory = collect_server_inventory(
            ssh_host="aiserver",
            timeout_seconds=15,
            runner=runner,
        )

        self.assertTrue(all(command[:3] == ("ssh", "--", "aiserver") for command in seen))
        self.assertEqual(inventory["server"], "aiserver")
        self.assertEqual(inventory["system"]["os"], "Ubuntu Test")
        self.assertEqual([vm["state"] for vm in inventory["vms"]], ["running", "shut off"])
        self.assertEqual(inventory["interfaces"][0]["addresses"][0]["address"], "2001:db8::10")
        self.assertEqual(inventory["listening_services"][0]["local"], "[::]:22")
        self.assertEqual(inventory["containers"][0]["state"], "exited")
        self.assertEqual(inventory["container_networks"][0]["name"], "pentest-lab")

    def test_rejects_unsafe_ssh_host_before_running_commands(self) -> None:
        with self.assertRaisesRegex(VirtualizationError, "invalid SSH host"):
            collect_server_inventory(ssh_host="server;whoami")


def _domain_xml(name: str, network: str, mac: str) -> str:
    return f"""
    <domain>
      <name>{name}</name>
      <uuid>{name}-uuid</uuid>
      <memory unit="KiB">2097152</memory>
      <vcpu>2</vcpu>
      <devices>
        <interface type="network">
          <mac address="{mac}"/>
          <source network="{network}"/>
          <model type="virtio"/>
        </interface>
      </devices>
    </domain>
    """


if __name__ == "__main__":
    unittest.main()
