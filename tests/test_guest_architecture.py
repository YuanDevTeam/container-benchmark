"""Native guest inputs remain consistent across ARM64 and AMD64 hosts."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import download_cache
from container_benchmark import guest_architecture as arch
from container_benchmark.interop import native_peer_releases


class GuestArchitectureTests(unittest.TestCase):
    def test_native_aliases_select_matching_rust_go_and_elf_identities(self):
        for native, expected, machine, elf in (
            ("ARM64", "arm64", "aarch64", 183),
            ("aarch64", "arm64", "aarch64", 183),
            ("AMD64", "amd64", "x86_64", 62),
            ("x86_64", "amd64", "x86_64", 62),
        ):
            with (
                self.subTest(native=native),
                patch.object(arch.platform, "machine", return_value=native),
            ):
                self.assertEqual(arch.architecture(), expected)
                self.assertEqual(arch.rust_target(), machine + "-unknown-linux-gnu")
                self.assertEqual(arch.musl_target(), machine + "-unknown-linux-musl")
                self.assertEqual(arch.elf_machine(), elf)
                self.assertEqual(arch.binary_format(), "ELF64 little-endian " + machine)
                self.assertEqual(
                    arch.v2ray_arch(), "arm64-v8a" if expected == "arm64" else "64"
                )

    def test_other_host_architecture_fails_instead_of_selecting_an_emulated_guest(self):
        with (
            patch.object(arch.platform, "machine", return_value="riscv64"),
            self.assertRaisesRegex(RuntimeError, "native ARM64 or AMD64"),
        ):
            arch.architecture()

    def test_official_peer_binary_must_match_the_selected_native_guest(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "peer"
            for native, selected, rejected in (("ARM64", 183, 62), ("AMD64", 62, 183)):
                with (
                    self.subTest(native=native),
                    patch.object(arch.platform, "machine", return_value=native),
                ):
                    header = bytearray(64)
                    header[:7] = b"\x7fELF\x02\x01\x01"
                    header[16:18] = (2).to_bytes(2, "little")
                    header[18:20] = selected.to_bytes(2, "little")
                    binary.write_bytes(header)
                    native_peer_releases._check_binary(binary)
                    header[18:20] = rejected.to_bytes(2, "little")
                    binary.write_bytes(header)
                    with self.assertRaisesRegex(ValueError, "native peer"):
                        native_peer_releases._check_binary(binary)

    def test_release_cache_keeps_native_architectures_in_separate_entries(self):
        prepared = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def prepare(staging):
                prepared.append(arch.architecture())
                header = bytearray(64)
                header[:7] = b"\x7fELF\x02\x01\x01"
                header[16:18] = (2).to_bytes(2, "little")
                header[18:20] = arch.elf_machine().to_bytes(2, "little")
                (staging / "peer").write_bytes(header)
                return {"architecture": arch.architecture()}

            with patch.object(download_cache, "CACHE_ROOT", root / "cache"):
                for native in ("ARM64", "AMD64", "ARM64"):
                    with patch.object(arch.platform, "machine", return_value=native):
                        run = root / native
                        run.mkdir(exist_ok=True)
                        record = native_peer_releases._copy_cached(
                            run, "peer", prepare, release="v1.0.0"
                        )
                        self.assertEqual(record["architecture"], arch.architecture())
            self.assertEqual(prepared, ["arm64", "amd64"])


if __name__ == "__main__":
    unittest.main()
