"""Offline native endpoint allocation; no guest, key generator or network runs."""

import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import wireguard_peer as wireguard
from container_benchmark.interop import masque_interop as masque


class NativePeerBatchFactoryTests(unittest.TestCase):
    def test_masque_instances_keep_dns_ports_and_witnesses_independent(self):
        origin = SimpleNamespace(ipv4="192.0.2.10")
        peer = SimpleNamespace(ipv4="192.0.2.11")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            for name in (
                "masque-client-public.der",
                "masque-client-key.der",
                "masque-server-public.der",
            ):
                (root / "peer" / name).write_bytes(b"synthetic-key")
            definitions = masque.cases(["masque"])
            for index, original in enumerate((definitions[4], definitions[5])):
                instance = f"batch-{index}"
                case = original | {
                    "port": 31000 + index,
                    "pressure_aux_base": 36000 + index * 8,
                    "pressure_instance": instance,
                }
                dns_port = case["pressure_aux_base"] + 4
                with patch.object(masque, "_keys"):
                    commands = masque.configure(
                        [case],
                        root,
                        origin,
                        peer,
                        instance=instance,
                        dns_port=dns_port,
                        pressure_targets={origin.ipv4: origin.ipv4},
                    )
                argv = commands[0]["argv"]
                config = json.loads((root / "peer" / Path(argv[-1]).name).read_text())
                node = masque.node(case, peer.ipv4, root / "peer", instance=instance)
                self.assertEqual(config["listen"], f"0.0.0.0:{case['port']}")
                self.assertEqual(node["port"], case["port"])
                self.assertEqual(node["dns"], [f"{peer.ipv4}:{dns_port}"])
                witness = masque.witness_path(root, case, instance=instance)
                self.assertEqual(Path(config["witness"]).name, witness.name)
                self.assertIn(instance, witness.name)
                endpoint_port = commands[0].get(
                    "udp_ports", commands[0].get("ready_ports")
                )
                self.assertEqual(endpoint_port, [case["port"]])
            configs = sorted((root / "peer").glob("*-batch-*.json"))
            self.assertEqual(len(configs), 2)
            tables = [json.loads(path.read_text())["network_table"] for path in configs]
            self.assertEqual(len(set(tables)), 2)

    def test_masque_remapped_port_does_not_admit_undeclared_semantics(self):
        case = deepcopy(masque.cases(["masque"])[0])
        case.update(port=31000, network="undeclared-transport")
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaises(ValueError),
        ):
            masque.configure([case], Path(directory), SimpleNamespace())

    def test_wireguard_instances_use_the_same_assigned_port_in_node_and_server(self):
        material = {"PrivateKey": "synthetic-private", "PublicKey": "synthetic-public"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            endpoints = []
            for port in (31000, 31001):
                path = root / str(port)
                (path / "peer").mkdir(parents=True)
                with patch.object(wireguard, "_keypair", return_value=material):
                    node, commands = wireguard.configure(
                        path,
                        SimpleNamespace(ipv4="192.0.2.11"),
                        port=port,
                        instance=f"batch-{port}",
                    )
                endpoint = json.loads((path / "peer/wg-endpoint.json").read_text())
                self.assertEqual(endpoint["port"], port)
                self.assertEqual(node["port"], port)
                self.assertEqual(node["ip"], endpoint["client_ip"])
                self.assertEqual(commands[0]["udp_ports"], [port])
                self.assertLessEqual(len(endpoint["device"]), 15)
                key_path = path / "peer/wg-key"
                self.assertEqual(key_path.read_text(), material["PrivateKey"] + "\n")
                if os.name != "nt":
                    self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                endpoints.append(endpoint)
            self.assertNotEqual(endpoints[0]["device"], endpoints[1]["device"])
            self.assertTrue(
                all(e["client_ip"] == wireguard.CLIENT_IP for e in endpoints)
            )

    def test_wireguard_default_endpoint_remains_unchanged(self):
        material = {"PrivateKey": "synthetic-private", "PublicKey": "synthetic-public"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            with patch.object(wireguard, "_keypair", return_value=material):
                node, _ = wireguard.configure(root, SimpleNamespace(ipv4="192.0.2.11"))
            endpoint = json.loads((root / "peer/wg-endpoint.json").read_text())
            self.assertEqual(node["port"], wireguard.PORT)
            self.assertEqual(node["ip"], wireguard.CLIENT_IP)
            self.assertEqual(endpoint["device"], wireguard.DEVICE)
            self.assertEqual(endpoint["prefix"], 24)


if __name__ == "__main__":
    unittest.main()
