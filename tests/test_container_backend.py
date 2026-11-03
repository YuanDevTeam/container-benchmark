"""Manager adapters preserve identities and owned-resource cleanup offline."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import container_backend as backend
from container_benchmark import containers, ownership


def container(name, *, labels=None, state="running"):
    return {
        "Name": "/" + name,
        "Config": {"Labels": labels or {}},
        "HostConfig": {"NanoCpus": 5_000_000_000, "Memory": 4 * 1024**3},
        "State": {"Status": state},
        "NetworkSettings": {
            "Networks": {
                "benchmark-nat": {
                    "IPAddress": "192.0.2.2",
                    "IPPrefixLen": 24,
                    "GlobalIPv6Address": "2001:db8::2",
                    "GlobalIPv6PrefixLen": 64,
                }
            }
        },
    }


class ContainerBackendTests(unittest.TestCase):
    def setUp(self):
        backend._run_options.cache_clear()
        self.addCleanup(backend._run_options.cache_clear)
        self.enterContext(
            patch.object(backend.platform, "system", return_value="Windows")
        )
        self.enterContext(
            patch.object(backend.platform, "machine", return_value="AMD64")
        )

    def test_mac_commands_and_json_remain_verbatim(self):
        original = '[ {"id": "apple-peer", "configuration": {}} ]\n'
        argv = ["container", "run", "--arch", "arm64", "image", "--guest-option"]
        with (
            patch.object(backend.platform, "system", return_value="Darwin"),
            patch.object(backend.platform, "machine", return_value="arm64"),
            patch.object(backend, "_native", return_value=original) as execute,
        ):
            self.assertEqual(backend.run_argv(argv), argv)
            self.assertEqual(
                backend.command("inspect", "apple-peer", timeout=17), original
            )
        execute.assert_called_once_with(
            ["container", "inspect", "apple-peer"], timeout=17
        )

    def test_windows_tun_namespace_preparation_requires_observed_ipv6_enablement(self):
        for before in ({"all": 1, "default": 1}, {"all": 0, "default": 0}):
            state = {"before": before, "after": {"all": 0, "default": 0}}
            execute = Mock(return_value=json.dumps(state))
            with self.subTest(before=before):
                observed = backend.prepare_tun_namespace(
                    "owned-runtime", execute=execute
                )
                self.assertEqual(observed, state)
                execute.assert_called_once()
                self.assertEqual(
                    execute.call_args.args[:4],
                    ("exec", "owned-runtime", "/bin/sh", "-ec"),
                )
                self.assertIsInstance(execute.call_args.args[4], str)

    def test_windows_tun_namespace_preparation_rejects_failed_or_invalid_readbacks(
        self,
    ):
        for after in (
            {"all": 1, "default": 0},
            {"all": 0, "default": 1},
            {"all": False, "default": 0},
            {"all": "0", "default": 0},
            {"all": 0},
        ):
            with (
                self.subTest(after=after),
                self.assertRaisesRegex(RuntimeError, "IPv6"),
            ):
                backend.prepare_tun_namespace(
                    "owned-runtime",
                    execute=Mock(
                        return_value=json.dumps(
                            {"before": {"all": 1, "default": 1}, "after": after}
                        )
                    ),
                )
        with self.assertRaisesRegex(RuntimeError, "permission denied"):
            backend.prepare_tun_namespace(
                "owned-runtime",
                execute=Mock(side_effect=backend.ContainerError("permission denied")),
            )

    def test_non_windows_tun_namespace_preparation_never_executes_a_command(self):
        execute = Mock(side_effect=AssertionError("unexpected manager call"))
        with patch.object(backend.platform, "system", return_value="Darwin"):
            self.assertIsNone(
                backend.prepare_tun_namespace("owned-runtime", execute=execute)
            )
        execute.assert_not_called()

    def test_localized_windows_diagnostics_and_utf8_json_preserve_text(self):
        with (
            patch.object(backend.locale, "getencoding", return_value="cp936"),
            patch.object(backend.subprocess, "run") as execute,
        ):
            execute.return_value = SimpleNamespace(
                returncode=1, stdout=b"", stderr="找不到网络".encode("cp936")
            )
            with self.assertRaisesRegex(backend.ContainerError, "找不到网络"):
                backend._native(["wslc", "network", "inspect", "missing"])
            execute.return_value = SimpleNamespace(
                returncode=0, stdout='{"name":"网络"}'.encode(), stderr=b""
            )
            self.assertEqual(backend._native(["wslc", "list"]), '{"name":"网络"}')

    def test_windows_run_translates_only_manager_arguments(self):
        guest = ["/bin/sh", "-c", "printf '%s' '--arch arm64'", "--network", "guest"]
        mount = "type=bind,source=D:\\owned files,target=/work,readonly"
        argv = [
            "container",
            "run",
            "--detach",
            "--name",
            "owned-peer",
            "--arch",
            "amd64",
            "--network",
            "default,mtu=1500",
            "--cpus",
            "5",
            "--memory",
            "4G",
            "--mount",
            mount,
            "docker.io/library/ubuntu:26.04",
            *guest,
        ]
        expected = [
            "wslc",
            "run",
            "--detach",
            "--name",
            "owned-peer",
            "--network",
            "bridge",
            "--cpus",
            "5",
            "--memory",
            "4G",
            "--mount",
            mount,
            "docker.io/library/ubuntu:26.04",
            *guest,
        ]
        self.assertEqual(backend.run_argv(argv), expected)
        named = backend.run_argv(
            [
                "container",
                "run",
                "--network",
                "benchmark-nat,mtu=1500",
                "image",
                *guest,
            ]
        )
        self.assertEqual(
            named, ["wslc", "run", "--network", "benchmark-nat", "image", *guest]
        )
        self.assertEqual(
            backend.run_argv(["git", "status", "--short"]), ["git", "status", "--short"]
        )

    def test_missing_capability_options_fail_before_a_container_launch(self):
        with patch.object(
            backend, "_native", return_value="--cpus --memory"
        ) as execute:
            with self.assertRaisesRegex(backend.ContainerError, "required by real TUN"):
                backend.ensure_runtime()
            with self.assertRaisesRegex(backend.ContainerError, "missing --cap-add"):
                backend.command(
                    "run", "--cap-add", "NET_ADMIN", "image", "sleep", "infinity"
                )
        execute.assert_called_once_with(["wslc", "run", "--help"])

    def test_supported_capabilities_are_forwarded_without_changing_guest_flags(self):
        with patch.object(backend, "_native", return_value="--cap-add --cap-drop"):
            backend.ensure_runtime()
            self.assertEqual(
                backend.run_argv(
                    [
                        "container",
                        "run",
                        "--cap-add",
                        "NET_ADMIN",
                        "--cap-drop",
                        "ALL",
                        "image",
                        "command",
                        "--cap-drop",
                        "guest-value",
                    ]
                ),
                [
                    "wslc",
                    "run",
                    "--cap-add",
                    "NET_ADMIN",
                    "--cap-drop",
                    "ALL",
                    "image",
                    "command",
                    "--cap-drop",
                    "guest-value",
                ],
            )

    def test_windows_rejects_per_guest_kernels_and_emulated_architectures(self):
        for arguments, reason in (
            (["--kernel", "D:\\owned\\kernel"], "WSL session kernel"),
            (["--arch", "arm64"], "native Linux guest architecture"),
            (["--network", "default,mtu=9000"], "network attachment option"),
        ):
            with (
                self.subTest(arguments=arguments),
                patch.object(backend, "_native") as execute,
                self.assertRaisesRegex(backend.ContainerError, reason),
            ):
                backend.command("run", *arguments, "image", "sleep", "infinity")
            execute.assert_not_called()

    def test_windows_ndjson_inventory_inspects_exact_names_for_labels_and_resources(
        self,
    ):
        labels = {"purpose": ownership.PURPOSE, "benchmark-run": "0123456789ab"}
        names = ["owned-first", "owned-second"]

        def execute(argv, *, timeout):
            self.assertEqual(timeout, 19)
            if argv == ["wslc", "list", "--all", "--format", "json"]:
                return "\n".join(
                    json.dumps({"Names": name, "Labels": "untrusted"}) for name in names
                )
            self.assertEqual(argv[:2], ["wslc", "inspect"])
            self.assertIn(argv[2], names)
            return json.dumps([container(argv[2], labels=labels)])

        with patch.object(backend, "_native", side_effect=execute) as native:
            rows = json.loads(
                backend.command("list", "--all", "--format", "json", timeout=19)
            )
        self.assertEqual(native.call_count, 3)
        self.assertEqual([row["id"] for row in rows], names)
        for row in rows:
            self.assertEqual(row["configuration"]["labels"], labels)
            self.assertEqual(
                row["configuration"]["resources"],
                {"cpus": 5, "memoryInBytes": 4 * 1024**3},
            )
            self.assertEqual(row["status"]["state"], "running")
            self.assertEqual(
                row["status"]["networks"][0]["ipv4Address"], "192.0.2.2/24"
            )
            self.assertEqual(
                row["status"]["networks"][0]["ipv6Address"], "2001:db8::2/64"
            )

    def test_image_inspection_uses_registry_manifest_digest_and_rejects_config_only(
        self,
    ):
        manifest = "sha256:" + "a" * 64
        config = "sha256:" + "b" * 64
        image = {
            "Id": config,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": ["ubuntu@" + manifest],
        }
        with patch.object(backend, "_native", return_value=json.dumps([image])):
            row = json.loads(backend.command("image", "inspect", "ubuntu:26.04"))[0]
        self.assertEqual(row["id"], config)
        self.assertEqual(row["configuration"]["name"], "docker.io/library/ubuntu:26.04")
        self.assertEqual(row["configuration"]["descriptor"]["digest"], manifest)
        for digests in ([], ["ubuntu@not-a-manifest-digest"]):
            with (
                self.subTest(digests=digests),
                patch.object(
                    backend,
                    "_native",
                    return_value=json.dumps(image | {"RepoDigests": digests}),
                ),
                self.assertRaisesRegex(
                    backend.ContainerError, "registry manifest digest"
                ),
            ):
                backend.command("image", "inspect", "ubuntu:26.04")

    def test_windows_image_must_match_the_native_linux_guest(self):
        for system, architecture in (("windows", "amd64"), ("linux", "arm64")):
            image = {
                "Id": "sha256:" + "b" * 64,
                "Os": system,
                "Architecture": architecture,
                "RepoDigests": ["ubuntu@sha256:" + "a" * 64],
            }
            with (
                self.subTest(system=system, architecture=architecture),
                patch.object(backend, "_native", return_value=json.dumps(image)),
                self.assertRaisesRegex(backend.ContainerError, "native Linux guest"),
            ):
                backend.command("image", "inspect", "ubuntu:26.04")

    def test_image_manifest_must_belong_to_the_requested_repository_and_pin(self):
        wanted = "sha256:" + "a" * 64
        other = "sha256:" + "c" * 64
        image = {
            "Id": "sha256:" + "b" * 64,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": ["alpine@" + other, "ubuntu@" + wanted],
        }
        with patch.object(backend, "_native", return_value=json.dumps(image)):
            row = json.loads(
                backend.command("image", "inspect", "docker.io/library/ubuntu:26.04")
            )[0]
            self.assertEqual(row["configuration"]["descriptor"]["digest"], wanted)
            with self.assertRaises(backend.ContainerError):
                backend.command("image", "inspect", "docker.io/library/ubuntu@" + other)
        image["RepoDigests"] = ["alpine@" + other]
        with (
            patch.object(backend, "_native", return_value=json.dumps(image)),
            self.assertRaises(backend.ContainerError),
        ):
            backend.command("image", "inspect", "docker.io/library/ubuntu:26.04")

    def test_image_inventory_normalizes_tags_and_digest_aliases(self):
        manifest = "sha256:" + "a" * 64
        config = "sha256:" + "b" * 64
        summary = "\n".join(
            [
                json.dumps({"Repository": "ubuntu", "Tag": "26.04"}),
                json.dumps({"Repository": "<none>", "Tag": "<none>"}),
            ]
        )
        inspected = {
            "Id": config,
            "RepoTags": ["ubuntu:26.04", "library/ubuntu:latest"],
            "RepoDigests": ["ubuntu@" + manifest],
        }
        with patch.object(
            backend, "_native", side_effect=[summary, json.dumps([inspected])]
        ) as execute:
            rows = json.loads(backend.command("image", "list", "--format", "json"))
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(
            {row["configuration"]["name"] for row in rows},
            {
                "docker.io/library/ubuntu:26.04",
                "docker.io/library/ubuntu:latest",
                "docker.io/library/ubuntu@" + manifest,
            },
        )
        self.assertTrue(all(row["id"] == config for row in rows))

    def test_windows_readiness_checks_guest_loopback_without_a_host_connection(self):
        lab = SimpleNamespace(run_id="0123456789ab")
        with patch.object(ownership, "register_container"):
            peer = containers.ContainerPeer(lab, Path("offline-origin"), "origin")
        inspected = json.dumps(
            [
                {
                    "status": {
                        "state": "running",
                        "networks": [{"ipv4Address": "192.0.2.2/24"}],
                    }
                }
            ]
        )
        with (
            patch.object(containers, "command", side_effect=[inspected, ""]) as execute,
            patch.object(
                containers.socket,
                "create_connection",
                side_effect=AssertionError("host socket"),
            ) as host,
        ):
            peer.wait_tcp(24500)
        self.assertTrue(peer.record["ready"])
        host.assert_not_called()
        self.assertEqual(execute.call_args_list[0].args, ("inspect", peer.name))
        arguments = execute.call_args_list[1].args
        self.assertEqual(arguments[:5], ("exec", peer.name, "python3", "-B", "-c"))
        self.assertIn("'127.0.0.1'", arguments[5])
        self.assertEqual(arguments[6], "24500")
        self.assertEqual(execute.call_args_list[1].kwargs, {"timeout": 5})

    def test_nat_normalization_requires_bridge_masquerading_and_external_access(self):
        for driver, internal, masquerade, expected in (
            ("bridge", False, "true", "nat"),
            ("bridge", True, "true", "bridge"),
            ("bridge", False, "false", "bridge"),
            ("host", False, "true", "host"),
        ):
            row = {
                "Name": "benchmark-nat",
                "Driver": driver,
                "Internal": internal,
                "Labels": {"purpose": ownership.PURPOSE},
                "Options": {
                    "com.docker.network.bridge.enable_ip_masquerade": masquerade
                },
            }
            with (
                self.subTest(driver=driver, internal=internal, masquerade=masquerade),
                patch.object(backend, "_native", return_value=json.dumps([row])),
            ):
                actual = json.loads(
                    backend.command("network", "inspect", "benchmark-nat")
                )[0]
            self.assertEqual(actual["configuration"]["mode"], expected)
            self.assertEqual(actual["configuration"]["labels"], row["Labels"])

    def test_nat_creation_and_delete_verbs_use_wslc_contract(self):
        self.assertEqual(
            backend.run_argv(
                [
                    "container",
                    "network",
                    "create",
                    "--label",
                    "purpose=test",
                    "benchmark-nat",
                ]
            ),
            [
                "wslc",
                "network",
                "create",
                "--driver",
                "bridge",
                "--opt",
                "com.docker.network.driver.mtu=1500",
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=true",
                "--label",
                "purpose=test",
                "benchmark-nat",
            ],
        )
        self.assertEqual(
            backend.run_argv(["container", "delete", "--force", "owned"]),
            ["wslc", "remove", "--force", "owned"],
        )
        self.assertEqual(
            backend.run_argv(["container", "image", "delete", "ubuntu:26.04"]),
            ["wslc", "image", "remove", "ubuntu:26.04"],
        )
        self.assertEqual(
            backend.run_argv(["container", "network", "delete", "benchmark-nat"]),
            ["wslc", "network", "remove", "benchmark-nat"],
        )

    def test_owned_cleanup_rechecks_inspected_labels_and_preserves_other_containers(
        self,
    ):
        run_id = "0123456789ab"
        owned = f"benchmark-{run_id}-core"
        borrowed = f"benchmark-{run_id}-unregistered"
        changed = f"benchmark-{run_id}-changed"
        matching = {"purpose": ownership.PURPOSE, "benchmark-run": run_id}
        rows = {
            owned: container(owned, labels=matching),
            borrowed: container(borrowed, labels=matching),
            changed: container(
                changed, labels=matching | {"benchmark-run": "other-run"}
            ),
        }
        mutations = []

        def execute(argv, *, timeout):
            if argv == ["wslc", "list", "--all", "--format", "json"]:
                return "\n".join(
                    json.dumps({"Names": name, "Labels": "purpose=spoofed"})
                    for name in rows
                )
            if argv[:2] == ["wslc", "inspect"]:
                return json.dumps([rows[argv[2]]])
            mutations.append(argv)
            self.assertEqual(argv[-1], owned)
            if argv[1] == "stop":
                rows[owned]["State"]["Status"] = "exited"
            elif argv[1] == "remove":
                del rows[owned]
            else:
                self.fail("unexpected mutation: " + repr(argv))
            return ""

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(
                os.environ,
                {"BENCHMARK_SESSION_ACTIVE": "1", "BENCHMARK_WORK_DIR": temporary},
            ),
            patch.object(backend, "_native", side_effect=execute),
        ):
            work = Path(temporary)
            (work / ".owned-session").write_text("offline synthetic ownership")
            ownership.initialize(work)
            for name in (owned, changed):
                ownership.register_container(name, run_id=run_id)
            errors = ownership.cleanup(work)
        self.assertEqual(
            mutations,
            [
                ["wslc", "stop", "--time", "5", owned],
                ["wslc", "remove", "--force", owned],
            ],
        )
        self.assertEqual(set(rows), {borrowed, changed})
        self.assertTrue(any("ownership mismatch" in error for error in errors))
        self.assertTrue(
            any("registered container remains" in error for error in errors)
        )


if __name__ == "__main__":
    unittest.main()
