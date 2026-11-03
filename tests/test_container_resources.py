"""Only dedicated builders receive the larger, fixed memory allocation."""

import unittest

from container_benchmark import container_resources as resources


class ContainerResourceTests(unittest.TestCase):
    def test_dedicated_builder_roles_or_explicit_source_use_16_gib(self):
        for role, source in (
            ("builder", False),
            ("tls-cover-builder", False),
            ("masque-builder", False),
            ("transparency-builder", True),
            ("source-compiler", True),
        ):
            arguments, memory = resources.allocation(role, source=source)
            self.assertEqual(arguments, ("--cpus", "5", "--memory", "16G"))
            self.assertEqual(memory, 16 * 1024**3)

    def test_runtime_roles_keep_4_gib_including_peer_helper_builds(self):
        for role in (
            "core",
            "consumer",
            "mihomo-consumer",
            "peer",
            "protocol-peer",
            "origin",
            "packages",
        ):
            arguments, memory = resources.allocation(role)
            self.assertEqual(arguments, ("--cpus", "5", "--memory", "4G"))
            self.assertEqual(memory, 4 * 1024**3)


if __name__ == "__main__":
    unittest.main()
