"""Offline checks for the small cache and exact-resource cleanup contract."""

import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import containers, download_cache, ownership, session
from container_benchmark import guest_architecture as arch
from container_benchmark.interop import mihomo_lab


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(mihomo_lab.container_backend, "ensure_runtime"))
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.enterContext(
            patch.object(download_cache, "CACHE_ROOT", self.root / "cache")
        )
        self.enterContext(
            patch.dict(
                os.environ,
                {"BENCHMARK_SESSION_ACTIVE": "0", "BENCHMARK_CACHE_FREEZE": "0"},
            )
        )
        self.prepared = []

    def prepare(self, staging):
        version = len(self.prepared) + 1
        self.prepared.append(version)
        (staging / "binary").write_text(f"version-{version}")
        return {"version": version}

    def owned_work(self):
        work = self.root / "owned"
        work.mkdir()
        (work / ".owned-session").write_text("test")
        ownership.initialize(work)
        os.environ.update(BENCHMARK_WORK_DIR=str(work), BENCHMARK_SESSION_ACTIVE="1")
        return work

    def test_guest_identity_requires_ubuntu_26_04_lts(self):
        release = 'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04.1 LTS"\nVERSION_ID="26.04"\n'
        self.assertEqual(
            containers.ubuntu_identity(release),
            {"os": "Ubuntu 26.04.1 LTS", "os_version": "26.04"},
        )
        with self.assertRaisesRegex(RuntimeError, "Ubuntu 26.04"):
            containers.ubuntu_identity(release.replace("26.04", "24.04"))

    def test_image_cache_does_not_reuse_the_previous_latest_tag(self):
        old_tag = "docker.io/library/ubuntu:latest"
        old_digest, new_digest = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        download_cache.daily(
            "container-image:" + old_tag + ":linux-arm64",
            lambda _: {"tag": old_tag, "digest": old_digest},
        )

        def command(*arguments, **_):
            if arguments[:2] == ("image", "inspect"):
                return json.dumps(
                    [{"configuration": {"descriptor": {"digest": new_digest}}}]
                )
            return ""

        with patch.object(containers, "command", side_effect=command) as operation:
            actual = containers.shared_image()
        self.assertEqual(actual["tag"], "docker.io/library/ubuntu:26.04")
        self.assertEqual(actual["digest"], new_digest)
        operation.assert_any_call("image", "pull", containers.IMAGE, timeout=180)

    def test_interop_image_cache_does_not_reuse_the_unversioned_entry(self):
        new_digest = "sha256:" + "2" * 64
        with patch.object(mihomo_lab, "CACHE", self.root / "interop"):
            mihomo_lab.daily(
                "image",
                lambda _: {
                    "tag": "docker.io/library/ubuntu:latest",
                    "digest": "sha256:" + "1" * 64,
                },
            )
            with (
                patch.object(
                    mihomo_lab,
                    "command",
                    return_value=json.dumps(
                        [{"configuration": {"descriptor": {"digest": new_digest}}}]
                    ),
                ) as operation,
                patch.object(
                    mihomo_lab, "Guest", side_effect=RuntimeError("packages reached")
                ) as guest,
                self.assertRaisesRegex(RuntimeError, "packages reached"),
            ):
                mihomo_lab.prepare_tools(SimpleNamespace(work=self.root))
            operation.assert_any_call("image", "pull", containers.IMAGE, timeout=180)
            self.assertEqual(
                guest.call_args.args[1], "docker.io/library/ubuntu@" + new_digest
            )

    def test_interop_cached_image_pulls_missing_frozen_digest(self):
        digest = "sha256:" + "2" * 64
        image = "docker.io/library/ubuntu@" + digest
        calls = []

        def command(*arguments, **kwargs):
            calls.append((arguments, kwargs))
            if len(calls) == 1:
                raise RuntimeError("pinned image missing")
            return ""

        with patch.object(mihomo_lab, "CACHE", self.root / "interop"):
            mihomo_lab.daily(
                "image-ubuntu-26.04-linux-" + arch.architecture(),
                lambda _: {"tag": containers.IMAGE, "digest": digest},
            )
            with (
                patch.object(mihomo_lab, "command", side_effect=command),
                patch.object(
                    mihomo_lab, "Guest", side_effect=RuntimeError("packages reached")
                ) as guest,
                self.assertRaisesRegex(RuntimeError, "packages reached"),
            ):
                mihomo_lab.prepare_tools(SimpleNamespace(work=self.root))
        self.assertEqual(
            calls,
            [
                (("image", "inspect", image), {}),
                (("image", "pull", image), {"timeout": 180}),
                (("image", "inspect", image), {}),
            ],
        )
        self.assertEqual(guest.call_args.args[1], image)

    def test_interop_frozen_digest_pull_and_reinspection_failures_propagate(self):
        digest = "sha256:" + "2" * 64
        image = "docker.io/library/ubuntu@" + digest
        for failed_call in (2, 3):
            with (
                self.subTest(failed_call=failed_call),
                tempfile.TemporaryDirectory(dir=self.root) as directory,
                patch.object(mihomo_lab, "CACHE", Path(directory) / "interop"),
            ):
                mihomo_lab.daily(
                    "image-ubuntu-26.04-linux-" + arch.architecture(),
                    lambda _: {"tag": containers.IMAGE, "digest": digest},
                )
                calls = []

                def command(*arguments, calls=calls, failed_call=failed_call, **_):
                    calls.append(arguments)
                    if len(calls) == 1:
                        raise RuntimeError("pinned image missing")
                    if len(calls) == failed_call:
                        raise RuntimeError("frozen digest operation failed")
                    return ""

                with (
                    patch.object(mihomo_lab, "command", side_effect=command),
                    patch.object(mihomo_lab, "Guest") as guest,
                    self.assertRaisesRegex(RuntimeError, "frozen digest operation"),
                ):
                    mihomo_lab.prepare_tools(SimpleNamespace(work=self.root))
                self.assertEqual(
                    calls,
                    [
                        ("image", "inspect", image),
                        ("image", "pull", image),
                        ("image", "inspect", image),
                    ][:failed_call],
                )
                guest.assert_not_called()

    def test_daily_hit_keeps_shared_payload_separate_from_consumer(self):
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            first = download_cache.daily(
                "release", self.prepare, directory=self.root / "first"
            )
            (self.root / "first/binary").write_text("consumer changed it")
            second = download_cache.daily(
                "release", self.prepare, directory=self.root / "second"
            )
        self.assertEqual(self.prepared, [1])
        self.assertFalse(first["cache"]["hit"])
        self.assertTrue(second["cache"]["hit"])
        self.assertEqual((self.root / "second/binary").read_text(), "version-1")

    def test_next_local_day_refreshes_dependency(self):
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            download_cache.daily("release", self.prepare)
        with patch.object(download_cache, "today", return_value="2026-10-06"):
            result = download_cache.daily(
                "release", self.prepare, directory=self.root / "consumer"
            )
        self.assertEqual(self.prepared, [1, 2])
        self.assertEqual(result["cache"], {"checked_on": "2026-10-06", "hit": False})
        self.assertEqual((self.root / "consumer/binary").read_text(), "version-2")

    def test_same_day_damaged_shared_payload_is_rechecked(self):
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            download_cache.daily("release", self.prepare)
            payload = next((self.root / "cache").glob("*/payload-*/binary"))
            payload.write_text("damaged")
            result = download_cache.daily(
                "release", self.prepare, directory=self.root / "consumer"
            )
        self.assertEqual(self.prepared, [1, 2])
        self.assertFalse(result["cache"]["hit"])
        self.assertEqual((self.root / "consumer/binary").read_text(), "version-2")

    def test_session_snapshot_stays_frozen_and_rejects_corruption(self):
        work = self.owned_work()
        os.environ["BENCHMARK_CACHE_FREEZE"] = "1"
        with patch.object(download_cache, "today", return_value="2026-10-05"):
            download_cache.daily("release", self.prepare)
        with patch.object(download_cache, "today", return_value="2026-10-06"):
            frozen = download_cache.daily("release", self.prepare)
            self.assertEqual(frozen["version"], 1)
            self.assertEqual(frozen["cache"]["checked_on"], "2026-10-05")
            payload = next((work / "dependency-snapshots").glob("*/payload-*/binary"))
            payload.write_text("damaged")
            with self.assertRaisesRegex(RuntimeError, "snapshot integrity changed"):
                download_cache.daily("release", self.prepare)
        self.assertEqual(self.prepared, [1])

    def test_session_saves_text_before_cleanup_and_restores_environment(self):
        previous = {
            name: os.environ.get(name)
            for name in (
                "BENCHMARK_WORK_DIR",
                "BENCHMARK_SESSION_ACTIVE",
                "BENCHMARK_CACHE_FREEZE",
                "GOCACHE",
                "PYTHONDONTWRITEBYTECODE",
            )
        }
        previous_bytecode = sys.dont_write_bytecode
        real_rmtree = shutil.rmtree
        saved, read_only = [], []
        external = self.root / "external-sdk"
        external.mkdir()
        (external / "source.go").write_text("outside owned scratch")
        (external / "source.go").chmod(0o444)
        external.chmod(0o555)
        self.addCleanup(external.chmod, 0o755)

        def restore_fixture():
            for directory in read_only:
                if directory.exists():
                    directory.chmod(0o755)

        self.addCleanup(restore_fixture)

        def remove_after_save(path):
            reports = list((self.root / "conclusions").glob("*.md"))
            self.assertEqual(len(reports), 1)
            saved.append(reports[0].read_text())
            self.assertIn("matched workload complete", saved[-1])
            self.assertIn("scratch cleanup pending", saved[-1])
            for directory in read_only:
                self.assertTrue(directory.stat().st_mode & stat.S_IWUSR)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o555)
            self.assertEqual(
                stat.S_IMODE((external / "source.go").stat().st_mode), 0o444
            )
            real_rmtree(path)

        with (
            patch.object(session, "BENCHMARK_ROOT", self.root),
            patch.object(session.ownership, "cleanup", return_value=[]) as cleanup,
            patch.object(session.shutil, "rmtree", side_effect=remove_after_save),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with session.Session(["compare", "--core", "mihomo"]) as run:
                (run.work / "summary.md").write_text("matched workload complete")
                module = run.work / "go-modules/example.com/sdk@v1/pkg"
                module.mkdir(parents=True)
                (module / "source.go").write_text("private copied SDK")
                (module / "source.go").chmod(0o444)
                (module / "external").symlink_to(external, target_is_directory=True)
                read_only[:] = [module.parent, module]
                for directory in read_only:
                    directory.chmod(0o555)
                run.status = "COMPLETED"
                self.assertTrue(sys.dont_write_bytecode)
                self.assertEqual(os.environ["BENCHMARK_WORK_DIR"], str(run.work))
            cleanup.assert_called_once_with(run.work)
        self.assertEqual(len(saved), 1)
        self.assertFalse(run.work.exists())
        self.assertEqual((external / "source.go").read_text(), "outside owned scratch")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o555)
        self.assertIn("Cleanup: complete", run.report.read_text())
        self.assertEqual(sys.dont_write_bytecode, previous_bytecode)
        self.assertEqual({name: os.environ.get(name) for name in previous}, previous)

    def test_cleanup_changes_only_registered_matching_container(self):
        work = self.owned_work()
        run_id = "0123456789ab"
        owned = f"benchmark-{run_id}-core"
        unregistered = f"benchmark-{run_id}-unregistered"
        labels = {"purpose": ownership.PURPOSE, "benchmark-run": run_id}
        rows = {
            name: {
                "id": name,
                "configuration": {"labels": labels},
                "status": {"state": "running"},
            }
            for name in (owned, unregistered, "unrelated-service")
        }
        before = json.dumps(rows, sort_keys=True)
        ownership.register_container(owned, run_id=run_id)
        mutations = []

        def container_cli(*arguments, **kwargs):
            if arguments == ("list", "--all", "--format", "json"):
                return json.dumps(list(rows.values()))
            mutations.append(arguments)
            self.assertEqual(arguments[-1], owned)
            if arguments[0] == "delete":
                del rows[owned]
            elif arguments[0] != "stop":
                self.fail(f"unexpected CLI mutation: {arguments}")
            return ""

        with patch.object(ownership, "_run", side_effect=container_cli):
            self.assertEqual(ownership.cleanup(work), [])
        self.assertEqual(
            mutations,
            [("stop", "--time", "5", owned), ("delete", "--force", owned)],
        )
        self.assertEqual(
            rows,
            {name: row for name, row in json.loads(before).items() if name != owned},
        )

    def test_final_report_replace_failure_keeps_saved_text(self):
        for frontend in ("comparison", "interop"):
            with (
                self.subTest(frontend=frontend),
                tempfile.TemporaryDirectory(dir=self.root) as directory,
                contextlib.ExitStack() as stack,
            ):
                root = Path(directory)
                if frontend == "comparison":
                    stack.enter_context(patch.object(session, "BENCHMARK_ROOT", root))
                    stack.enter_context(
                        patch.object(ownership, "cleanup", return_value=[])
                    )
                    run = session.Session(["compare"])
                    reports = root / "conclusions"
                else:
                    stack.enter_context(
                        patch.object(mihomo_lab, "SCRATCH", root / "work")
                    )
                    reports = root / "conclusions"
                    stack.enter_context(
                        patch.object(mihomo_lab, "CONCLUSIONS", reports)
                    )
                    stack.enter_context(
                        patch.object(
                            mihomo_lab.platform, "system", return_value="Darwin"
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            mihomo_lab.platform, "machine", return_value="arm64"
                        )
                    )
                    run = mihomo_lab.Session()
                replace = os.replace
                writes = 0

                def fail_final(source, destination, replace=replace):
                    nonlocal writes
                    writes += 1
                    if writes == 2:
                        raise OSError("fixture final report failure")
                    replace(source, destination)

                with (
                    patch.object(os, "replace", side_effect=fail_final),
                    self.assertRaisesRegex(OSError, "final report failure"),
                    run,
                ):
                    (run.work / "summary.md").write_text("verified case result")
                self.assertEqual(writes, 2)
                self.assertFalse(run.work.exists())
                report = next(reports.glob("*.md")).read_text()
                self.assertIn("verified case result", report)
                self.assertIn("scratch cleanup pending", report)
                self.assertFalse(list(reports.glob("*.tmp")))

    def test_cleanup_rechecks_ownership_after_stop_before_deleting(self):
        for frontend in ("peer", "interop", "recovery"):
            for changed in ("purpose", "run"):
                with (
                    self.subTest(frontend=frontend, changed=changed),
                    tempfile.TemporaryDirectory(dir=self.root) as directory,
                    patch.dict(os.environ, {"BENCHMARK_SESSION_ACTIVE": "0"}),
                ):
                    work = Path(directory)
                    owner = SimpleNamespace(work=work, run_id="0123456789ab", guests=[])
                    if frontend == "interop":
                        target, method = mihomo_lab, "command"
                        guest = target.Guest(owner, "official", "core")
                        run_label = "vole-run"
                    else:
                        target, method = containers, "command"
                        guest = target.ContainerPeer(owner, work, "core")
                        run_label = "benchmark-run"
                    if frontend == "recovery":
                        target, method = ownership, "_run"
                        (work / ".owned-session").write_text("test")
                        ownership.initialize(work)
                        os.environ.update(
                            BENCHMARK_SESSION_ACTIVE="1", BENCHMARK_WORK_DIR=str(work)
                        )
                        ownership.register_container(guest.name, run_id=owner.run_id)
                    row = {
                        "id": guest.name,
                        "configuration": {
                            "labels": {
                                "purpose": target.PURPOSE,
                                run_label: owner.run_id,
                            }
                        },
                        "status": {"state": "running"},
                    }
                    mutations = []

                    def command(
                        *arguments,
                        row=row,
                        mutations=mutations,
                        name=guest.name,
                        key="purpose" if changed == "purpose" else run_label,
                        **_kwargs,
                    ):
                        if arguments == ("list", "--all", "--format", "json"):
                            return json.dumps([row])
                        mutations.append(arguments)
                        self.assertEqual(arguments, ("stop", "--time", "5", name))
                        row["configuration"]["labels"][key] = "another-owner"
                        row["status"]["state"] = "stopped"
                        return ""

                    with patch.object(target, method, side_effect=command):
                        if frontend == "recovery":
                            errors = ownership.cleanup(work)
                            self.assertTrue(
                                any("ownership changed" in e for e in errors)
                            )
                            self.assertTrue(work.exists())
                        else:
                            with self.assertRaisesRegex(
                                RuntimeError, "ownership changed"
                            ):
                                guest.stop()
                            self.assertFalse(guest.record["joined"])
                    self.assertEqual(mutations, [("stop", "--time", "5", guest.name)])


if __name__ == "__main__":
    unittest.main()
