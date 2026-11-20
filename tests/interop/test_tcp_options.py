"""Offline resource-boundary checks for fixture-owned TCP metric removal."""

import contextlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark.interop import tcp_options as fixture

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/interop/tcp_options"
SPEC = importlib.util.spec_from_file_location(
    "tcp_options_gate_common", FIXTURE / "gate_common.py"
)
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)


def result(output=b"", *, code=0, cleanup=True):
    return SimpleNamespace(returncode=code, stdout=output, cleanup=cleanup, reason=None)


class TcpMetricsOwnershipTests(unittest.TestCase):
    def test_empty_dump_is_absent_without_flushing(self):
        with patch.object(COMMON, "run_command", return_value=result(b"\n")) as run:
            COMMON.clear_tcp_metrics("127.77.0.21")
        self.assertTrue(run.call_args_list)
        self.assertTrue(all("flush" not in call.args[0] for call in run.call_args_list))

    def test_removes_only_the_exact_owned_destination(self):
        owned, foreign = "127.77.0.21", "127.77.0.210"
        entries = {owned, foreign, "198.19.0.90"}
        removed = []

        def execute(arguments, **_kwargs):
            if "flush" in arguments:
                self.assertEqual(arguments[-2], "address")
                removed.append(arguments[-1])
                entries.remove(arguments[-1])
                return result()
            return result(
                (
                    "\n" + "\n".join(address + " age 1sec" for address in entries)
                ).encode()
            )

        with patch.object(COMMON, "run_command", side_effect=execute):
            COMMON.clear_tcp_metrics(owned)
            COMMON.clear_tcp_metrics(owned)
        self.assertEqual(removed, [owned])
        self.assertEqual(entries, {foreign, "198.19.0.90"})

    def test_ip_errors_are_not_treated_as_absence(self):
        present = result(b"127.77.0.21 age 1sec\n")
        failures = (
            [result(code=1)],
            [present, result(code=1)],
            [present, result(), result(code=1)],
            [result(cleanup=False)],
        )
        for responses in failures:
            with (
                self.subTest(responses=responses),
                patch.object(COMMON, "run_command", side_effect=responses),
                self.assertRaises(RuntimeError),
            ):
                COMMON.clear_tcp_metrics("127.77.0.21")


class SharedModuleBaselineTests(unittest.TestCase):
    def test_absence_only_selection_records_not_applicable_without_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with (
                patch.object(fixture, "Session") as session,
                patch.object(fixture, "official_mihomo") as download,
                patch.object(fixture.options, "module_context") as modules,
            ):
                fixture.run(
                    Path("nonexistent-source"),
                    None,
                    output,
                    ["brutal-h2mux-local-absent"],
                )
            session.assert_not_called()
            download.assert_not_called()
            modules.assert_not_called()
            report = json.loads(output.read_text())
            self.assertEqual(report["status"], "NOT_APPLICABLE")
            self.assertFalse(report["network_executed"])
            self.assertEqual(report["results"], [])
            self.assertIn(
                "keeps TCP Brutal loaded", report["not_applicable_cases"][0]["reason"]
            )

    def test_guest_cannot_request_a_module_absent_execution_group(self):
        with (
            patch.object(fixture, "isolated"),
            patch.object(fixture.reference, "_load_probe") as load,
            self.assertRaisesRegex(ValueError, "retain the shared loaded"),
        ):
            fixture.guest(Path("nonexistent-work"), "absent")
        load.assert_not_called()

    def test_mixed_selection_keeps_mptcp_and_server_disabled_and_reports_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "input-vole"
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(header)
            output = root / "report.json"
            session = SimpleNamespace(work=root, status="ERROR")
            commands = []

            class Guest:
                def __init__(self, _root, _image, *, role):
                    self.role = role
                    self.name = "offline-" + role
                    self.record = {}
                    self.ipv4 = "192.0.2.2" if role == "protocol-peer" else "192.0.2.3"

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    return False

                def execute(self, argv, _log, **_kwargs):
                    commands.append(argv)
                    if self.role == "protocol-peer":
                        (root / "tcp-options-peer-result.json").write_text(
                            json.dumps({"status": "PASS"})
                        )
                    elif "guest" in argv:
                        selected = json.loads(
                            (root / "tcp-options-fixture.json").read_text()
                        )
                        (root / "tcp-options-present.json").write_text(
                            json.dumps(
                                {
                                    "status": "PASS",
                                    "cases": [
                                        {"id": case, "status": "PASS"}
                                        for case in selected["cases"]
                                    ],
                                }
                            )
                        )

            with (
                patch.object(fixture, "architecture", return_value="arm64"),
                patch.object(fixture, "elf_machine", return_value=183),
                patch.object(
                    fixture, "Session", return_value=contextlib.nullcontext(session)
                ),
                patch.object(fixture.reference, "_source_identity", return_value={}),
                patch.object(fixture.reference, "_certificate", return_value="pin"),
                patch.object(fixture, "official_mihomo", return_value={}),
                patch.object(fixture, "prepare_tools", return_value=("image", {})),
                patch.object(fixture, "prepare_peers"),
                patch.object(fixture, "wait_for"),
                patch.object(
                    fixture,
                    "multipath_environment",
                    return_value=contextlib.nullcontext({}),
                ),
                patch.object(
                    fixture.options,
                    "module_context",
                    side_effect=lambda *_args, **_kwargs: contextlib.nullcontext({}),
                ) as modules,
                patch("container_benchmark.linux_builder.LinuxGuest", Guest),
                patch("container_benchmark.interop.mihomo_lab.install_tools"),
            ):
                fixture.run(
                    root,
                    binary,
                    output,
                    [
                        "mptcp-negotiated",
                        "brutal-h2mux-server-disabled",
                        "brutal-h2mux-local-absent",
                    ],
                )
            report = json.loads(output.read_text())
            self.assertEqual(report["status"], "PARTIAL")
            self.assertEqual(session.status, "PARTIAL")
            self.assertEqual(
                {case["id"] for case in report["results"][0]["cases"]},
                {"mptcp-negotiated", "brutal-h2mux-server-disabled"},
            )
            self.assertEqual(
                report["not_applicable_cases"][0]["status"], "NOT_APPLICABLE"
            )
            self.assertTrue(
                all(call.kwargs.get("enabled", True) for call in modules.call_args_list)
            )
            self.assertFalse(any("absent" in argv for argv in commands))


if __name__ == "__main__":
    unittest.main()
