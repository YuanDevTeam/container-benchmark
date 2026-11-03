"""Offline protocol fixture/ownership checks; never start listeners or containers."""

import contextlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.cli import main
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.interop import mihomo_lab as lab


class InteropTests(unittest.TestCase):
    def test_mihomo_listener_protocols_and_three_ss_algorithms_are_explicit(self):
        cases = interop.cases(interop.PROTOCOLS)
        self.assertEqual(len(cases), 33)
        self.assertEqual(len({case["port"] for case in cases}), 33)
        self.assertEqual(
            {case["protocol"] for case in cases},
            set(interop.PROTOCOLS) - {"mieru", "masque"},
        )
        self.assertEqual(
            [
                case["cipher"]
                for case in cases
                if case["id"] in dict(interop.SS_CIPHERS)
            ],
            [cipher for cipher, _ in interop.SS_CIPHERS],
        )

    def test_native_ss_and_uot_keep_the_strict_boundaries_in_the_catalog(self):
        cases = interop.cases(["ss"])
        enabled = {
            case["id"]
            for case in cases
            if case.get("probe_options", {}).get("ss2022_boundaries")
        }
        self.assertEqual(
            enabled,
            {
                cipher + suffix
                for cipher, _ in interop.SS_CIPHERS
                for suffix in ("", "-uot-v2")
            },
        )
        self.assertTrue(
            all(not case.get("shadow_tls") for case in cases if case["id"] in enabled)
        )

    def test_list_is_offline_and_does_not_create_a_lab(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                main(["interop", "--backend", "mihomo", "--list"]),
                0,
            )
        self.assertEqual(len(output.getvalue().splitlines()), 42)

    def test_native_backend_selection_is_offline_and_explicit(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                main(["interop", "--backend", "xray", "--list"]),
                0,
            )
        rows = output.getvalue().splitlines()
        self.assertEqual(len(rows), 17)
        self.assertTrue(all("xray" in row for row in rows))

    def test_default_catalog_retains_all_native_supplements_without_duplicates(self):
        catalog = interop.selected_cases(interop.PROTOCOLS, interop.BACKENDS)
        self.assertEqual(len(catalog), 89)
        self.assertEqual(len({case["id"] for case in catalog}), 89)
        self.assertEqual(
            {
                name: sum(case["backend"] == name for case in catalog)
                for name in interop.BACKENDS
            },
            {
                "mihomo": 42,
                "tuic": 2,
                "shadowsocks-rust": 4,
                "xray": 17,
                "hysteria2": 3,
                "v2ray": 9,
                "caddy": 3,
                "trusttunnel": 0,
                "mieru": 0,
                "masque": 9,
            },
        )
        self.assertEqual(
            sum(case.get("expected", "pass") != "pass" for case in catalog), 6
        )
        self.assertEqual(len(interop.selected_cases(["hysteria2"], ["hysteria2"])), 3)
        with self.assertRaisesRegex(ValueError, "empty"):
            interop.selected_cases(["socks5"], ["caddy"])
        with self.assertRaisesRegex(ValueError, "empty"):
            interop.selected_cases(["ss"], ["xray"])

    def test_named_listeners_and_client_certificate_policy_match(self):
        for case in interop.cases(interop.PROTOCOLS):
            with self.subTest(case=case["id"]):
                server = interop.listener(
                    case, "/work/peer/cert.pem", "/work/peer/key.pem", "192.0.2.2:24501"
                )
                client = interop.node(case, "192.0.2.1", "a" * 64)
                self.assertEqual(server["port"], client["port"])
                self.assertEqual(server["proxy"], "DIRECT")
                self.assertEqual(
                    client["udp"],
                    not case.get("probe_options", {}).get("tcp_only", False),
                )
                if case["protocol"] in ("anytls", "trojan", "hysteria2", "tuic"):
                    self.assertEqual(client["fingerprint"], "a" * 64)
                    self.assertFalse(client["skip-cert-verify"])
                if case["protocol"] in ("hysteria2", "tuic"):
                    self.assertEqual(server["alpn"], client["alpn"])
                    self.assertEqual(client["alpn"], ["h3"])
                if case["protocol"] == "vless":
                    self.assertTrue(server["allow-insecure"])
                if case["protocol"] == "vmess":
                    self.assertNotIn("allow-insecure", server)

    def test_production_cli_config_requires_a_real_tun_and_loopback_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            path = interop.configure_client(
                Path(directory), interop.cases(["tuic"])[0], "192.0.2.1", "b" * 64
            )
            config = json.loads(path.read_text())
        self.assertNotIn("mixed-port", config)
        self.assertTrue(config["tun"]["enable"])
        self.assertNotIn("file-descriptor", config["tun"])
        self.assertEqual(config["external-controller"], "127.0.0.1:9090")
        self.assertNotIn("port", config)
        self.assertNotIn("socks-port", config)
        self.assertFalse(config["allow-lan"])
        self.assertEqual(config["rules"], ["MATCH,edge"])

    def test_domain_udp_keeps_fake_ip_and_uses_controlled_real_dns(self):
        from container_benchmark.interop.xray_interop import cases

        case = cases(["trojan"])[0]
        original = json.loads(json.dumps(case))
        with tempfile.TemporaryDirectory() as directory:
            path = interop.configure_client(
                Path(directory),
                case,
                "192.0.2.1",
                "b" * 64,
                domain_dns="192.0.2.2:24004",
            )
            config = json.loads(path.read_text())
        self.assertEqual(config["dns"]["nameserver"], ["192.0.2.2:24004"])
        self.assertEqual(config["dns"]["enhanced-mode"], "fake-ip")
        self.assertEqual(config["dns"]["fake-ip-range"], "198.19.0.1/16")
        self.assertEqual(config["dns"]["fake-ip-filter"], [])
        self.assertNotIn("hosts", config)
        self.assertNotIn("hosts", config["dns"])
        self.assertEqual(case, original)
        self.assertEqual(case["probe_options"]["udp_target"], "origin.fixture.invalid")

    def test_daily_cache_does_not_refresh_today_and_rejects_corruption(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "CACHE", Path(directory)),
        ):
            prepare = Mock(
                side_effect=lambda staging: (
                    (staging / "binary").write_bytes(b"official"),
                    {"identity": "latest"},
                )[1]
            )
            cached, identity = lab.daily("example", prepare)
            self.assertEqual(lab.daily("example", prepare)[1], identity)
            self.assertEqual(prepare.call_count, 1)
            (cached / "binary").write_bytes(b"corrupted")
            lab.daily("example", prepare)
            self.assertEqual(prepare.call_count, 2)

    def test_daily_rust_check_reuses_an_archive_matching_the_new_official_manifest(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "rust").mkdir()
            archive = cache / "rust/rust.tar.xz"
            with tarfile.open(archive, "w:xz") as package:
                entry = tarfile.TarInfo("rust-1.99.0-" + lab.TARGET + "/install.sh")
                entry.size = 3
                package.addfile(entry, io.BytesIO(b"sdk"))
            checksum = lab.sha256(archive)

            def download(url, path, *, limit):
                self.assertTrue(url.endswith("channel-rust-stable.toml"))
                path.write_text(
                    '[pkg.rust]\nversion = "1.99.0 stable"\n'
                    f"[pkg.rust.target.{lab.TARGET}]\navailable = true\n"
                    'xz_url = "https://static.rust-lang.org/dist/official.tar.xz"\n'
                    f'xz_hash = "{checksum}"\n'
                )

            with (
                patch.object(lab, "CACHE", cache),
                patch.object(lab, "download", side_effect=download) as fetched,
            ):
                cached, identity = lab.official_rust()
            self.assertEqual(fetched.call_count, 1)
            self.assertEqual(identity["archive_sha256"], checksum)
            self.assertEqual(lab.sha256(cached / "rust.tar.xz"), checksum)
            self.assertEqual(identity["installer_files"], [entry.name])

    def test_capability_variants_are_current_and_ss_has_no_native_udp_fallback(self):
        cases = interop.cases(interop.PROTOCOLS)
        self.assertEqual(sum(bool(case.get("upgrade")) for case in cases), 6)
        self.assertEqual(sum(bool(case.get("shadow_tls")) for case in cases), 6)
        self.assertEqual(sum(bool(case.get("uot")) for case in cases), 7)
        for case in cases:
            client = interop.node(case, "192.0.2.1", "a" * 64)
            server = interop.listener(case, "cert", "key", "192.0.2.2:24501")
            if case.get("uot"):
                if case["protocol"] == "ss":
                    self.assertFalse(server["udp"])
                if case["protocol"] == "tuic":
                    self.assertTrue(client["udp-over-stream"])
                    self.assertEqual(client["udp-over-stream-version"], 2)
                    self.assertNotIn("udp-over-tcp", client)
                else:
                    self.assertEqual(client["udp-over-tcp-version"], 2)
            if case.get("shadow_tls"):
                self.assertEqual(client["plugin-opts"]["version"], 3)
                self.assertTrue(server["shadow-tls"]["strict-mode"])
                self.assertFalse(client["plugin-opts"]["skip-cert-verify"])
            if case.get("upgrade"):
                self.assertEqual(
                    client["ws-opts"]["v2ray-http-upgrade-fast-open"], case["fast"]
                )
        self.assertEqual(
            interop.node(
                next(case for case in cases if case["id"] == "tuic-quic"),
                "192.0.2.1",
                "a" * 64,
            )["udp-relay-mode"],
            "quic",
        )

    def test_cache_does_not_follow_symlink_or_relative_paths(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "CACHE", Path(directory)),
        ):
            entry = Path(directory) / "example"
            entry.mkdir()
            lab.save(entry / "identity.json", {"files": {"../outside": "a" * 64}})
            with self.assertRaisesRegex(ValueError, "single-level"):
                lab.daily("example", Mock())

    def test_safe_reasons_never_copy_native_error_or_credentials(self):
        self.assertEqual(
            interop._safe_reason(ValueError("password=do-not-print")), "ValueError"
        )

    def test_offline_apt_install_uses_the_actual_deb_cache_path(self):
        guest = SimpleNamespace(root=Path("/owned"), name="fake", execute=Mock())
        lab.install_tools(guest)
        command = guest.execute.call_args.args[0]
        self.assertIn("-o Dir::Cache::archives=/work/builder-tools", command[2])
        self.assertIn("--no-download", command[2])
        self.assertEqual(
            interop._safe_reason(ValueError("UDP origin source differs")),
            "UDP origin source differs",
        )

    def test_interop_packages_satisfy_the_shared_peer_builder_preflight(self):
        from container_benchmark.linux_builder import PACKAGES

        self.assertTrue(set(PACKAGES).issubset(lab.PACKAGES))

    def test_backend_failure_evidence_preserves_the_original_exception(self):
        selected = [
            next(
                case
                for case in interop.selected_cases(["tuic"], ["tuic"])
                if case["id"] == "tuic"
            )
        ]
        for reason in (None, "owned fixture stopped before business"):
            with (
                self.subTest(reason=reason),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                (root / "results").mkdir()
                primary = RuntimeError("original owned consumer failure")
                failure = {"kind": "RuntimeError", "message": str(primary)}
                failed_case = {"id": "tuic", "status": "ERROR"}
                result = {
                    "status": "ERROR",
                    "cases": [failed_case],
                    "failure": failure,
                }
                expected = {"failure": failure}
                if reason is not None:
                    result["reason"] = expected["reason"] = reason
                report = {"containers": {}, "cases": []}

                def guest_factory(*args, **kwargs):
                    guest = Mock(record={})
                    guest.__enter__ = Mock(return_value=guest)
                    guest.__exit__ = Mock(return_value=False)
                    return guest

                def fail_install(guest, root=root, result=result, primary=primary):
                    (root / "results/tuic.json").write_text(json.dumps(result))
                    raise primary

                with (
                    patch.object(lab, "Guest", side_effect=guest_factory),
                    patch.object(lab, "install_tools", side_effect=fail_install),
                    patch.object(
                        lab, "command", side_effect=AssertionError("no resources")
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(RuntimeError) as raised,
                ):
                    interop._run_backend(
                        SimpleNamespace(work=root),
                        "image",
                        "tuic",
                        selected,
                        "pin",
                        report,
                    )
                self.assertIs(raised.exception, primary)
                self.assertEqual(report["cases"], [failed_case])
                self.assertEqual(report["backend_failures"]["tuic"], expected)

    def test_failed_artifact_cleanup_cannot_leave_a_passing_conclusion(self):
        with (
            patch.object(lab.platform, "system", return_value="Darwin"),
            patch.object(lab.platform, "machine", return_value="arm64"),
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "SCRATCH", Path(directory) / "work"),
            patch.object(lab, "CONCLUSIONS", Path(directory) / "results"),
        ):
            session = lab.Session().__enter__()
            session.status = "PASS"
            with (
                patch.object(lab.shutil, "rmtree", side_effect=OSError),
                self.assertRaises(RuntimeError),
            ):
                session.__exit__(None, None, None)
            reports = list(lab.CONCLUSIONS.glob("*.md"))
            self.assertEqual(len(reports), 1)
            self.assertIn("Overall result: ERROR", reports[0].read_text())
            self.assertIn("artifact cleanup failed", reports[0].read_text())

    def test_report_write_failure_preserves_text_for_recovery(self):
        with (
            patch.object(lab.platform, "system", return_value="Darwin"),
            patch.object(lab.platform, "machine", return_value="arm64"),
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "SCRATCH", Path(directory) / "work"),
            patch.object(lab, "CONCLUSIONS", Path(directory) / "results"),
        ):
            session = lab.Session().__enter__()
            summary = session.work / "summary.md"
            summary.write_text("verified case result")
            original = Path.write_text

            def fail_report(path, text, *args, **kwargs):
                if path.parent == lab.CONCLUSIONS:
                    raise OSError("fixture report failure")
                return original(path, text, *args, **kwargs)

            with (
                patch.object(Path, "write_text", fail_report),
                self.assertRaises(OSError),
            ):
                session.__exit__(None, None, None)
            self.assertEqual(summary.read_text(), "verified case result")


if __name__ == "__main__":
    unittest.main()
