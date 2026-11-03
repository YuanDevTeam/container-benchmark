"""Offline cache/build ownership checks; no containers, compiler or network."""

import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import download_cache, ownership, wireguard_peer
from container_benchmark import guest_architecture as arch
from container_benchmark import peer_binary_cache as cache
from container_benchmark.container_resources import BUILDER_MEMORY_BYTES, allocation
from container_benchmark.inputs import sha256
from container_benchmark.interop import client_inputs, http_transparency
from container_benchmark.interop import masque_interop as masque


def elf():
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = arch.elf_machine().to_bytes(2, "little")
    return bytes(header)


class PeerBinaryCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "fixture"
        self.source.mkdir()
        (self.source / "main.go").write_text("package main\nfunc main() {}\n")
        (self.source / "go.mod").write_text("module example.test/owned\ngo 1.27.0\n")
        (self.source / "go.sum").write_text("")
        self.events = []
        self.builders = []
        owner = self

        class Builder:
            def __init__(self, root, image, **kwargs):
                self.root = root
                self.record = {"joined": False}
                self.peer = SimpleNamespace(stop=Mock())
                owner.builders.append(self)
                owner.assertEqual(kwargs["role"], "peer-binary-builder")
                owner.assertEqual(allocation(kwargs["role"])[1], BUILDER_MEMORY_BYTES)
                owner.assertTrue(root.is_relative_to(owner.base))
                owner.assertFalse(root.is_relative_to(owner.base / "cache"))
                owner.assertEqual(
                    kwargs["extra_mounts"], [(owner.source, "/peer-source")]
                )

            def __enter__(self):
                owner.events.append("start")
                return self

            def execute(self, argv, log, **_kwargs):
                if argv[-1] == "version":
                    log.write_text(f"go version go1.27.2 linux/{arch.architecture()}\n")
                elif argv[:2] == ["/bin/sh", "-ec"]:
                    owner.events.append("build")
                    owner.assertIn("GOTOOLCHAIN=local CGO_ENABLED=0", argv[2])
                    if (owner.source / "go.mod").exists():
                        owner.assertIn("build -mod=readonly -trimpath", argv[2])
                    else:
                        owner.assertIn("GO111MODULE=off", argv[2])
                        owner.assertNotIn("-mod=readonly", argv[2])
                        owner.assertIn("build -trimpath", argv[2])
                    name = re.search(r"/run/benchmark/artifacts/([a-z-]+)", argv[2])[1]
                    binary = self.root / "artifacts" / name
                    binary.write_bytes(elf())
                    binary.chmod(0o755)
                    log.write_text("synthetic compiler success\n")

            def __exit__(self, *_args):
                self.record["joined"] = True
                owner.events.append("joined")

        self.addCleanup(patch.stopall)
        patch.object(cache, "LinuxGuest", Builder).start()
        patch.object(cache, "install_tools").start()
        patch.object(download_cache, "CACHE_ROOT", self.base / "cache").start()
        patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "0"}).start()

    def prepare(self, name, **kwargs):
        root = self.base / name
        root.mkdir()
        (root / "builder-tools").mkdir()
        (root / "builder-tools/tools.deb").write_bytes(b"owned package fixture")
        (root / "go.tar.gz").write_bytes(b"owned Go archive fixture")
        toolchain = {
            "version": "go1.27.2",
            "archive_sha256": sha256(root / "go.tar.gz"),
        }
        identity = cache.prepare(
            root,
            "docker.io/library/ubuntu:26.04",
            "owned-peer",
            self.source,
            toolchain,
            self.base / "modules",
            **kwargs,
        )
        return root, identity

    def test_second_run_copies_final_elf_without_starting_builder(self):
        first, built = self.prepare("run-a")
        self.assertEqual(self.events, ["start", "build", "joined"])
        self.assertFalse(built["cache"]["hit"])
        (first / "artifacts/owned-peer").write_bytes(b"private run mutation")
        second, copied = self.prepare("run-b")
        self.assertTrue(copied["cache"]["hit"])
        self.assertEqual(len(self.builders), 1)
        self.assertEqual((second / "artifacts/owned-peer").read_bytes(), elf())
        self.assertEqual(
            list((second / "artifacts").iterdir()), [second / "artifacts/owned-peer"]
        )
        payloads = list((self.base / "cache").glob("*/payload-*"))
        self.assertEqual(len(payloads), 1)
        self.assertEqual([path.name for path in payloads[0].iterdir()], ["owned-peer"])
        self.assertTrue(all(builder.record["joined"] for builder in self.builders))

    def test_source_and_lock_changes_rebuild_instead_of_reusing_old_binary(self):
        self.prepare("run-a")
        (self.source / "main.go").write_text("package main\nfunc main() {println(1)}\n")
        self.prepare("run-b")
        (self.source / "go.sum").write_text("owned module checksum change\n")
        self.prepare("run-c")
        self.assertEqual(len(self.builders), 3)

    def test_failed_source_guard_does_not_publish_a_cache_payload(self):
        original = cache.source_files
        calls = 0

        def changed(path):
            nonlocal calls
            result = original(path)
            if path == self.source:
                calls += 1
                if calls > 1:
                    result["main.go"] = "changed"
            return result

        with (
            patch.object(cache, "source_files", side_effect=changed),
            self.assertRaisesRegex(RuntimeError, "sources changed during build"),
        ):
            self.prepare("run-a")
        self.assertEqual(self.events, ["start", "build", "joined"])
        self.assertFalse(list((self.base / "cache").glob("*/payload-*")))

    def test_legacy_interop_owner_also_retains_exact_builder_for_recovery(self):
        session = SimpleNamespace(guests=[])
        self.prepare("run-a", session=session)
        self.assertEqual(session.guests, [self.builders[0].peer])

    def test_stdlib_fixture_keeps_module_mode_off(self):
        (self.source / "go.mod").unlink()
        (self.source / "go.sum").unlink()
        self.prepare("run-a")
        self.assertEqual(self.events, ["start", "build", "joined"])

    def test_masque_runtime_only_requests_cached_elf(self):
        root = self.base / "run"
        root.mkdir()
        (root / "go.tar.gz").write_bytes(b"archive")
        guest = SimpleNamespace(image="owned-image", execute=Mock())
        identity = {"go_toolchain": {"version": "test"}, "sources": {}}
        with (
            patch.object(
                cache, "prepare", return_value={"binary_sha256": "ELF"}
            ) as prepare,
            patch.object(masque, "module_cache", return_value=self.base / "modules"),
        ):
            masque.build(guest, root, identity)
        guest.execute.assert_not_called()
        self.assertEqual(
            prepare.call_args.args[1:4], ("owned-image", "masque", masque.PEER_SOURCE)
        )
        self.assertEqual(identity["binary_sha256"], "ELF")
        self.assertFalse((root / "go.tar.gz").exists())

    def test_wireguard_source_is_frozen_and_runtime_only_executes_version(self):
        root = self.base / "runtime"
        root.mkdir()
        (root / "artifacts").mkdir()
        commit = "a" * 40
        source_cache = self.base / "official-source"
        source_cache.mkdir()
        with tarfile.open(source_cache / "source.tar.xz", "w:xz") as archive:
            for name, body in {
                "go.mod": b"module owned.test/wg\n",
                "go.sum": b"",
            }.items():
                entry = tarfile.TarInfo("wireguard-go-" + commit + "/" + name)
                entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body))

        def go(target):
            (target / "go.tar.gz").write_bytes(b"archive")
            return {"go_toolchain": {"version": "test"}}

        def compiled(target, *_args, **_kwargs):
            (target / "artifacts/wireguard-go").write_bytes(elf())
            return {"compiler_version": "synthetic compiler"}

        def execute(argv, log, **_kwargs):
            self.assertEqual(argv, ["/work/artifacts/wireguard-go", "--version"])
            log.write_text("official stable source version\n")

        guest = SimpleNamespace(image="owned-image", execute=Mock(side_effect=execute))
        session = self.base / "owned-session"
        session.mkdir()
        with (
            patch.object(
                wireguard_peer,
                "_source",
                return_value={
                    "commit": commit,
                    "url": "https://owned.invalid/source.tar.xz",
                },
            ) as resolved,
            patch.object(
                wireguard_peer,
                "download",
                side_effect=lambda _url, path, **_: shutil.copyfile(
                    source_cache / "source.tar.xz", path
                ),
            ) as download,
            patch.object(ownership, "_work", return_value=session),
            patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "1"}),
            patch.object(download_cache, "today", return_value="2040-01-01") as day,
            patch.object(masque, "prepare", side_effect=go),
            patch.object(masque, "module_cache", return_value=self.base / "modules"),
            patch.object(cache, "prepare", side_effect=compiled) as prepare,
        ):
            identity = wireguard_peer.prepare(root, guest)
            day.return_value = "2040-01-02"
            second = self.base / "runtime-two"
            (second / "artifacts").mkdir(parents=True)
            wireguard_peer.prepare(second, guest)
            self.assertEqual(resolved.call_count, 1)
            self.assertEqual(download.call_count, 1)
            self.assertEqual(
                (second / "wireguard-inputs/source.tar.xz").read_bytes(),
                (source_cache / "source.tar.xz").read_bytes(),
            )
            with patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "0"}):
                third = self.base / "runtime-three"
                (third / "artifacts").mkdir(parents=True)
                wireguard_peer.prepare(third, guest)
                self.assertEqual(resolved.call_count, 2)
                self.assertEqual(download.call_count, 1)
        self.assertEqual(guest.execute.call_count, 3)
        self.assertEqual(prepare.call_args.args[1:3], ("owned-image", "wireguard-go"))
        self.assertEqual(identity["runtime_version"], "official stable source version")
        self.assertEqual(identity["compiler_version"], "synthetic compiler")
        self.assertEqual(
            (root / "wireguard-inputs/source.tar.xz").read_bytes(),
            (source_cache / "source.tar.xz").read_bytes(),
        )

    def test_transparency_go_fixture_uses_cache_before_separate_grease_builder(self):
        root = self.base / "transparency"
        root.mkdir()
        (root / "artifacts").mkdir()
        source = self.base / "vole-source"
        include = source / "include"
        include.mkdir(parents=True)
        boring = self.base / ".cache/boring"
        (boring / "build").mkdir(parents=True)
        for name in ("libssl.a", "libcrypto.a"):
            (boring / "build" / name).write_bytes(b"owned BoringSSL fixture")
        session = SimpleNamespace(source_dir=source)
        commands = []

        class GreaseBuilder:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def execute(self, argv, *_args, **_kwargs):
                commands.append(argv)
                if argv[0] != "c++":
                    raise AssertionError("Go compilation leaked into GREASE builder")
                (root / "artifacts/http-grease").write_bytes(elf())

        def toolchain(_root):
            (root / "go.tar.gz").write_bytes(b"owned archive")
            return {"go_toolchain": {"version": "test"}}

        def compiled(*_args, **_kwargs):
            (root / "artifacts/http-transparency").write_bytes(elf())
            return {"binary_sha256": "owned cache ELF"}

        with (
            patch.object(http_transparency, "BENCHMARK_ROOT", self.base),
            patch.object(http_transparency, "Guest", GreaseBuilder),
            patch.object(http_transparency, "install_tools"),
            patch(
                "container_benchmark.core_vole_adapter.source_mounts", return_value=[]
            ),
            patch.object(masque, "prepare", side_effect=toolchain),
            patch.object(masque, "module_cache", return_value=self.base / "modules"),
            patch.object(cache, "prepare", side_effect=compiled) as prepare,
        ):
            http_transparency.build_fixture(
                session, "owned-image", root, boring, include
            )
        self.assertEqual(len(commands), 1)
        self.assertEqual(
            prepare.call_args.kwargs,
            {
                "package": "./transparency",
                "test": True,
                "session": session,
            },
        )

    def test_tls_cover_uses_the_same_final_elf_cache(self):
        root = self.base / "tls-cover"
        root.mkdir()
        session = SimpleNamespace(guests=[])

        def toolchain(_root):
            (root / "go.tar.gz").write_bytes(b"owned archive")
            return {"go_toolchain": {"version": "test"}}

        with (
            patch.object(masque, "prepare", side_effect=toolchain),
            patch.object(masque, "module_cache", return_value=self.base / "modules"),
            patch.object(
                cache, "prepare", return_value={"binary_sha256": "ELF"}
            ) as prepare,
        ):
            identity = client_inputs.prepare_tls_cover(session, "owned-image", root)
        self.assertEqual(
            prepare.call_args.args[1:4],
            (
                "owned-image",
                "tls-cover",
                client_inputs.reference.FIXTURE_ROOT / "tls_cover",
            ),
        )
        self.assertEqual(prepare.call_args.kwargs, {"session": session})
        self.assertEqual(identity["binary_sha256"], "ELF")
        self.assertFalse((root / "go.tar.gz").exists())

    def test_go_latest_is_session_frozen_and_unchanged_archive_is_reused_next_day(self):
        (self.source / "go.mod").write_text(
            "module owned.test/peer\nrequire (\n"
            "github.com/quic-go/quic-go v9.8.7\n"
            "github.com/quic-go/connect-ip-go v3.2.1\n"
            "golang.org/x/net v4.5.6\n)\n"
        )
        session = self.base / "owned-session"
        session.mkdir()
        selected = {"version": "go1.27.2"}

        def archive_bytes():
            return ("official archive " + selected["version"]).encode()

        def release(*_args, **_kwargs):
            import hashlib

            version = selected["version"]
            return io.BytesIO(
                json.dumps(
                    [
                        {
                            "version": version,
                            "stable": True,
                            "files": [
                                {
                                    "os": "linux",
                                    "arch": arch.architecture(),
                                    "kind": "archive",
                                    "filename": version
                                    + f".linux-{arch.architecture()}.tar.gz",
                                    "sha256": hashlib.sha256(
                                        archive_bytes()
                                    ).hexdigest(),
                                }
                            ],
                        }
                    ]
                ).encode()
            )

        def prepare(name):
            root = self.base / name
            root.mkdir()
            return root, masque.prepare(root)["go_toolchain"]

        with (
            patch.object(masque, "PEER_SOURCE", self.source),
            patch.object(masque, "CACHE", self.base / "legacy"),
            patch.object(ownership, "_work", return_value=session),
            patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "1"}),
            patch.object(download_cache, "today", return_value="2040-01-01") as day,
            patch.object(
                masque.urllib.request, "urlopen", side_effect=release
            ) as query,
            patch.object(
                masque,
                "download",
                side_effect=lambda _url, path, **_: path.write_bytes(archive_bytes()),
            ) as download,
        ):
            first_root, first = prepare("first")
            day.return_value = "2040-01-02"
            second_root, second = prepare("second")
            self.assertEqual(first["version"], second["version"])
            self.assertEqual(query.call_count, 1)
            self.assertEqual(download.call_count, 1)
            (first_root / "go.tar.gz").write_bytes(b"private changed copy")
            self.assertEqual((second_root / "go.tar.gz").read_bytes(), archive_bytes())
            with patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "0"}):
                _, third = prepare("third")
                self.assertEqual(query.call_count, 2)
                self.assertEqual(download.call_count, 1)
                self.assertTrue(third["archive_cache"]["hit"])
                day.return_value = "2040-01-03"
                selected["version"] = "go1.27.3"
                _, fourth = prepare("fourth")
                self.assertEqual(fourth["version"], "go1.27.3")
                self.assertEqual(query.call_count, 3)
                self.assertEqual(download.call_count, 2)


if __name__ == "__main__":
    unittest.main()
