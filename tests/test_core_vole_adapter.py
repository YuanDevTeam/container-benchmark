"""All pressure and comparison configurations are fixed to complete CN rules."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import core_vole_adapter as vole
from container_benchmark import linux_builder


class VoleAdapterTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.assets = self.root / "assets"
        self.assets.mkdir()
        for kind in ("geosite", "geoip"):
            (self.assets / f"{kind}.dat").write_bytes(kind.encode())
        self.origins = [
            SimpleNamespace(ipv4="192.0.2.2"),
            SimpleNamespace(ipv4="192.0.2.3"),
        ]
        self.witnesses = {"domain_positive": "example.cn"}

    def configure(self):
        result = vole.configure(
            self.root / "vole",
            self.assets,
            self.witnesses,
            self.origins,
            self.origins[1],
            SimpleNamespace(fd=11, device="tun0"),
        )
        return json.loads(result["config"].read_text())

    def test_normal_cli_declares_and_inherits_the_host_owned_raw_ip_fd(self):
        root = self.root / "vole"
        result = vole.configure(
            root,
            self.assets,
            self.witnesses,
            self.origins,
            self.origins[1],
            SimpleNamespace(fd=11, device="tun0"),
        )
        config = json.loads(result["config"].read_text())
        self.assertEqual(config["external-controller"], "127.0.0.1:9090")
        self.assertFalse(config["geo-auto-update"])
        self.assertEqual(
            config["tun"],
            {
                "enable": True,
                "file-descriptor": 11,
                "device": "tun0",
                "mtu": 1500,
                "dns-hijack": ["198.18.0.1:53"],
                "udp-timeout": 60,
            },
        )
        self.assertEqual(
            result["argv"],
            [
                str(root / "artifacts/vole"),
                "-d",
                str(root / "data"),
                "-f",
                str(root / "config.json"),
            ],
        )
        self.assertEqual(result["pass_fds"], (11,))
        self.assertFalse((root / "requests.jsonl").exists())
        for name in ("geosite.dat", "geoip.dat"):
            copied = root / "data/geodata" / name
            self.assertFalse(copied.is_symlink())
            self.assertEqual(copied.read_bytes(), (self.assets / name).read_bytes())

    def test_comparison_remains_cn_only_without_extra_selectors(self):
        config = self.configure()
        self.assertNotIn("nameserver-policy", config["dns"])
        self.assertEqual(
            config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,blocked",
            ],
        )

    def test_private_geodata_writes_do_not_modify_frozen_assets(self):
        self.configure()
        for name in ("geosite.dat", "geoip.dat"):
            with self.subTest(name=name):
                source = self.assets / name
                original = source.read_bytes()
                (self.root / "vole/data/geodata" / name).write_bytes(b"runtime data")
                self.assertEqual(source.read_bytes(), original)

    def test_extra_witness_categories_never_change_the_cn_workload(self):
        self.witnesses.update(
            geosite_codes=["cn", "google", "!cn", "google@ads"],
            geoip_codes=["cn", "us", "!cn"],
        )
        config = self.configure()
        self.assertNotIn("nameserver-policy", config["dns"])
        self.assertEqual(
            config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,blocked",
            ],
        )

    def prepare_build(self):
        root = self.root / "build"
        release = root / "vole-target/release"
        release.mkdir(parents=True)
        (root / "artifacts").mkdir()
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (183).to_bytes(2, "little")
        identity = b"Vole;engine=rust;coreVersion=0.1.0"
        (root / "artifacts/vole").write_bytes(header + identity)
        (root / "vole-version.log").write_text("Vole 0.1.0\n" + identity.decode())
        (release / "libvole.rlib").write_bytes(b"builder-only Rust library")
        source = self.root / "source"
        source.mkdir()
        (source / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n')
        (source / "Cargo.lock").write_text("locked dependencies")
        return root, Mock(sources={"vole": source})

    def test_build_records_cli_identity_and_builder_only_rlib(self):
        root, guest = self.prepare_build()
        identity = vole.build(guest, root)

        self.assertEqual(guest.execute.call_count, 2)
        self.assertEqual(
            guest.execute.call_args_list[0].args[0],
            [
                "env",
                "PYTHONPATH=/src/benchmark/src",
                "python3",
                "-B",
                "-m",
                "container_benchmark.core_vole_adapter",
            ],
        )
        self.assertEqual(identity["library_name"], "libvole.rlib")
        self.assertEqual(identity["features"], ["cli"])
        self.assertEqual(identity["library_format"], "rlib")
        self.assertEqual(identity["binary_format"], "ELF64 little-endian aarch64")
        self.assertEqual(
            identity["build_identity"], "Vole;engine=rust;coreVersion=0.1.0"
        )
        self.assertEqual(
            identity["library_sha256"],
            hashlib.sha256(b"builder-only Rust library").hexdigest(),
        )
        self.assertEqual(
            identity["lockfile_sha256"],
            hashlib.sha256(b"locked dependencies").hexdigest(),
        )

    def test_build_rejects_wrong_binary_architecture_or_identity(self):
        root, guest = self.prepare_build()
        binary = root / "artifacts/vole"
        original = binary.read_bytes()
        binary.write_bytes(original[:18] + (62).to_bytes(2, "little") + original[20:])
        with self.assertRaisesRegex(ValueError, "native Linux arm64 ELF"):
            vole.build(guest, root)
        binary.write_bytes(original)
        (root / "vole-version.log").write_text("Vole 0.2.0")
        with self.assertRaisesRegex(ValueError, "build identity"):
            vole.build(guest, root)
        (root / "vole-version.log").write_text("Vole;engine=rust;coreVersion=0.1.0")
        binary.write_bytes(original[:20] + b"other executable")
        with self.assertRaisesRegex(ValueError, "build identity"):
            vole.build(guest, root)

    def test_explicit_cli_reuses_frozen_binary_without_claiming_build_provenance(self):
        root, guest = self.prepare_build()
        selected = self.root / "selected-cli"
        selected.write_bytes((root / "artifacts/vole").read_bytes())
        with patch.object(vole, "source_identity", return_value={"commit": "selected"}):
            identity = vole.use_binary(guest, root, selected)
        guest.execute.assert_called_once_with(
            ["/run/benchmark/artifacts/vole", "-v"],
            root / "vole-version.log",
            timeout=30,
        )
        self.assertEqual(
            identity["binary_sha256"], hashlib.sha256(selected.read_bytes()).hexdigest()
        )
        self.assertEqual(identity["selected_source"], {"commit": "selected"})
        self.assertEqual(
            identity["build_provenance"], "external build evidence required"
        )
        self.assertNotIn("features", identity)
        self.assertNotIn("library_sha256", identity)
        self.assertEqual((root / "artifacts/vole").stat().st_mode & 0o777, 0o755)

    def test_explicit_cli_cannot_bypass_native_elf_check(self):
        root, guest = self.prepare_build()
        selected = self.root / "selected-cli"
        selected.write_bytes(b"not a native CLI")
        with self.assertRaisesRegex(ValueError, "native Linux arm64 ELF"):
            vole.use_binary(guest, root, selected)

    def test_guest_prepares_source_dependencies_for_the_same_normal_cargo_build(self):
        root, guest = self.prepare_build()
        source = guest.sources["vole"]
        (root / "vole-target/release/vole").write_bytes(b"normal CLI")
        cache = self.root / "native cache"
        scope = root / "vole-native.env"
        scope.write_text("STALE=discarded\n")
        suffix = "_AARCH64_UNKNOWN_LINUX_GNU"
        include, library = str(cache / "include"), str(cache / "lib")
        events = []

        def prepare(target, *, github_env):
            events.append("prepare")
            self.assertEqual(target, linux_builder.RUST_TARGET)
            self.assertEqual(github_env, scope)
            self.assertFalse(scope.exists())
            self.assertEqual(os.environ["VOLE_NATIVE_CACHE_DIR"], str(cache))
            scope.write_text(
                f"VOLE_BLAKE3_INCLUDE_DIR{suffix}={include}\n"
                f"VOLE_BLAKE3_LIB_DIR{suffix}={library}\n"
            )

        def compile_cli(argv, *, cwd, env, stdout, check):
            events.append("cargo")
            self.assertEqual(
                argv,
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--release",
                    "--no-default-features",
                    "--features",
                    "cli",
                    "--lib",
                    "--bin",
                    "vole",
                    "--message-format=json-render-diagnostics",
                ],
            )
            self.assertEqual(cwd, source)
            self.assertTrue(check)
            self.assertEqual(env["VOLE_BLAKE3_INCLUDE_DIR" + suffix], include)
            self.assertEqual(env["VOLE_BLAKE3_LIB_DIR" + suffix], library)
            self.assertEqual(env["CARGO_TARGET_DIR"], str(root / "vole-target"))
            self.assertNotIn("STALE", env)
            stdout.write('{"reason":"build-finished","success":true}\n')

        package = ModuleType("vole_scripts")
        package.__path__ = []
        builds = ModuleType("vole_scripts.builds")
        builds.prepare_native_dependencies = Mock(side_effect=prepare)
        before_path = sys.path.copy()
        with (
            patch.dict(
                sys.modules, {"vole_scripts": package, "vole_scripts.builds": builds}
            ),
            patch.object(vole.subprocess, "run", side_effect=compile_cli) as cargo,
        ):
            vole._guest_build(source=source, root=root, native_cache=cache)
            self.assertEqual(events, ["prepare", "cargo"])
            self.assertEqual(sys.path, before_path)
            self.assertEqual((root / "artifacts/vole").read_bytes(), b"normal CLI")
            self.assertTrue(
                json.loads((root / "vole-build-artifacts.jsonl").read_text())["success"]
            )
            cargo.reset_mock()
            builds.prepare_native_dependencies.side_effect = RuntimeError(
                "native prepare failed"
            )
            with self.assertRaisesRegex(RuntimeError, "native prepare failed"):
                vole._guest_build(source=source, root=root, native_cache=cache)
            cargo.assert_not_called()

    def test_native_cache_mount_is_separate_from_readonly_source_and_runtime(self):
        source = self.root / "source"
        source.mkdir()
        native_cache = self.root / "benchmark/.cache/vole-native-linux"
        peer = SimpleNamespace(name="owned-builder", record={}, stop=Mock())
        inspection = [
            {
                "configuration": {
                    "resources": {
                        "cpus": linux_builder.CPUS,
                        "memoryInBytes": 16 * 1024**3,
                    }
                },
                "status": {"networks": [{"mtu": 1500, "ipv4Address": "192.0.2.1/24"}]},
            }
        ]

        def command(action, *args, **kwargs):
            if action == "inspect":
                return json.dumps(inspection)
            if action == "exec" and args[-2:] == ("/bin/uname", "-r"):
                return "7.3.0-test"
            if action == "exec":
                return 'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04.1 LTS"\nVERSION_ID=26.04\n'
            return ""

        with (
            patch.object(linux_builder, "BENCHMARK_ROOT", self.root / "benchmark"),
            patch.object(linux_builder, "ContainerPeer", return_value=peer),
            patch.object(linux_builder, "command", side_effect=command) as executed,
        ):
            with linux_builder.LinuxGuest(
                self.root / "builder",
                "ubuntu",
                sources={"vole": source},
                network="default",
                role="builder",
            ):
                arguments = executed.call_args_list[0].args
                self.assertEqual(arguments[arguments.index("--cpus") + 1], "5")
                self.assertEqual(arguments[arguments.index("--memory") + 1], "16G")
                self.assertIn(
                    f"type=bind,source={source.resolve()},target=/src/cores/vole,readonly",
                    arguments,
                )
                self.assertIn(
                    f"type=bind,source={native_cache},"
                    f"target={linux_builder.NATIVE_CACHE_PATH}",
                    arguments,
                )
            executed.reset_mock()
            inspection[0]["configuration"]["resources"]["memoryInBytes"] = 8 * 1024**3
            with linux_builder.LinuxGuest(
                self.root / "runtime", "ubuntu", network="default"
            ):
                arguments = executed.call_args_list[0].args
                self.assertEqual(arguments[arguments.index("--cpus") + 1], "5")
                self.assertEqual(arguments[arguments.index("--memory") + 1], "8G")
                self.assertFalse(
                    any(
                        linux_builder.NATIVE_CACHE_PATH in str(arg) for arg in arguments
                    )
                )
            executed.reset_mock()
            with linux_builder.LinuxGuest(
                self.root / "runtime-with-source",
                "ubuntu",
                sources={"vole": source},
                network="default",
            ):
                arguments = executed.call_args_list[0].args
                self.assertEqual(arguments[arguments.index("--memory") + 1], "8G")
                self.assertIn(
                    f"type=bind,source={source.resolve()},target=/src/cores/vole,readonly",
                    arguments,
                )
        self.assertEqual(peer.stop.call_count, 3)
        self.assertTrue({"zip", "unzip"}.issubset(linux_builder.PACKAGES))
        with self.assertRaisesRegex(ValueError, "invalid explicit dependency mount"):
            linux_builder.LinuxGuest(
                self.root / "collision",
                "ubuntu",
                extra_mounts=[(source, linux_builder.NATIVE_CACHE_PATH)],
            )
