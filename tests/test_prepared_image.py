"""Exercise dependency image deduplication and OCI provenance offline."""

import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from container_benchmark import ownership
from container_benchmark import prepared_image as images

DIGEST = "sha256:" + "a" * 64


class PreparedImages(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(images, "CACHE", self.root / "cache"))
        self.enterContext(patch.object(images, "architecture", return_value="arm64"))
        self.enterContext(
            patch.multiple(
                ownership,
                share_image=Mock(),
                image_acquisition=Mock(side_effect=nullcontext),
            )
        )

    def test_reuse_restore_corruption_and_dependency_change(self):
        cache = {"hit": True, "checked_on": "2026-11-05"}
        base = {"tag": images.IMAGE, "digest": DIGEST, "cache": cache}
        packages = {
            "requested": ["clang"],
            "resolved": [{"name": "clang", "version": "21", "architecture": "arm64"}],
            "debs": {"clang.deb": "b" * 64},
            "resolverEnvironment": {"joined": True},
            "cache": cache,
        }
        tools = {
            "rust": {
                "version": "1.92",
                "target": "aarch64-unknown-linux-gnu",
                "archive_sha256": "c" * 64,
            },
            "go": {"version": "go1.27.3", "archive_sha256": "d" * 64},
            "cache": cache,
        }
        loaded = {}

        def build(destination, _reference, _marker, selected, _tools):
            (destination / "image.oci.tar").write_bytes(b"offline image")
            return {
                "installed": selected["resolved"],
                "builderJoined": True,
                "builderEnvironment": {"joined": True},
                "ociManifestDigest": DIGEST,
                "ociConfigDigest": DIGEST,
            }

        def load(_image, _operation, _flag, archive, **_options):
            reference = "localhost/vole-benchmark/ubuntu:" + Path(archive).parent.name
            loaded[reference] = DIGEST

        builder, loader = Mock(side_effect=build), Mock(side_effect=load)
        with patch.multiple(
            images,
            official_image=Mock(return_value=base),
            _resolve_packages=Mock(return_value=packages),
            _toolchains=Mock(return_value=tools),
            _build_image=builder,
            _inspect=loaded.get,
            command=loader,
        ):
            reference, first = images.ensure_prepared_image()
            self.assertFalse(first["cache"]["hit"])
            cache["checked_on"] = "2026-11-06"
            second, reused = images.ensure_prepared_image()
            self.assertEqual(reference, second)
            self.assertTrue(reused["cache"]["hit"])
            builder.assert_called_once()
            loader.assert_called_once()

            loaded.clear()
            self.assertEqual(images.ensure_prepared_image()[0], reference)
            builder.assert_called_once()
            self.assertEqual(loader.call_count, 2)
            Path(first["archivePath"]).write_bytes(b"corrupt")
            self.assertFalse(images.ensure_prepared_image()[1]["cache"]["hit"])
            self.assertEqual(builder.call_count, 2)

            packages["resolved"][0]["version"] = "22"
            next_reference, _ = images.ensure_prepared_image()
            self.assertNotEqual(next_reference, reference)
            tools["go"]["archive_sha256"] = "f" * 64
            self.assertNotEqual(images.ensure_prepared_image()[0], next_reference)
            self.assertEqual(builder.call_count, 4)

    def test_apt_candidate_preserves_dependency_release_and_architecture(self):
        candidate = (
            "Inst libc6 [2.43] (2.44 Ubuntu:26.04/resolute-updates, "
            "Ubuntu:26.04/resolute-security [arm64])"
        )
        self.assertEqual(
            images.apt_candidates(candidate + " [libc-bin:arm64 ]"),
            [{"name": "libc6", "version": "2.44", "architecture": "arm64"}],
        )
        with self.assertRaises(ValueError):
            images.apt_candidates(candidate + " [libc-bin:amd64 ]")

    def test_oci_digest_chain_and_runtime_directory_safety(self):
        layer, archive = self.root / "rootfs.tar", self.root / "image.oci.tar"

        def write_layer(name):
            with tarfile.open(layer, "w") as target:
                entry = tarfile.TarInfo(name)
                entry.size = 3
                target.addfile(entry, io.BytesIO(b"abc"))

        def read_blob(bundle, descriptor):
            digest = descriptor["digest"].removeprefix("sha256:")
            raw = bundle.extractfile("blobs/sha256/" + digest).read()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            return raw

        write_layer("usr/bin/public-tool")
        reference = "localhost/vole-benchmark/ubuntu:" + "a" * 64
        digest = images.write_oci_archive(layer, archive, reference, {})
        with tarfile.open(archive) as bundle:
            descriptor = json.load(bundle.extractfile("index.json"))["manifests"][0]
            self.assertEqual(descriptor["digest"], digest)
            manifest = json.loads(read_blob(bundle, descriptor))
            config = json.loads(read_blob(bundle, manifest["config"]))
            raw = gzip.decompress(read_blob(bundle, manifest["layers"][0]))
            self.assertEqual(
                config["rootfs"]["diff_ids"],
                ["sha256:" + hashlib.sha256(raw).hexdigest()],
            )
            with tarfile.open(fileobj=io.BytesIO(raw)) as rootfs:
                self.assertEqual(rootfs.getmember("tmp").mode, 0o1777)
                self.assertEqual(rootfs.getmember("root").mode, 0o700)
                self.assertEqual(
                    rootfs.extractfile("usr/bin/public-tool").read(), b"abc"
                )

        for name in ("run/benchmark/session.json", "root/private", "etc/hosts"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                write_layer(name)
                images.write_oci_archive(layer, archive, reference, {})
