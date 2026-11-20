"""Port publication is opt-in and rejects ambiguous or invalid bindings offline."""

import unittest

from container_benchmark.linux_builder import published_ports


class PublishedPortTests(unittest.TestCase):
    def test_default_does_not_publish_and_tcp_udp_can_share_a_number(self):
        self.assertEqual(published_ports(()), ())
        specifications = (
            "192.168.1.243:28180:28180/tcp",
            "192.168.1.243:28180:53/udp",
        )
        self.assertEqual(published_ports(specifications), specifications)

    def test_duplicate_host_binding_cannot_select_two_origins(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            published_ports(
                ("192.168.1.243:28180:80/tcp", "192.168.1.243:28180:81/tcp")
            )

    def test_explicit_wildcard_is_supported_by_the_shared_adapter(self):
        self.assertEqual(
            published_ports(("0.0.0.0:28180:80/tcp",)),
            ("0.0.0.0:28180:80/tcp",),
        )

    def test_invalid_bindings_fail_before_guest_acquisition(self):
        for specification in (
            "28180:80",
            "bad:28180:80/tcp",
            "192.168.1.243:0:80/tcp",
            "192.168.1.243:28180:65536/tcp",
            "192.168.1.243:28180:80/sctp",
            "192.168.1.243:28180:80/tcp --network host",
            None,
        ):
            with (
                self.subTest(specification=specification),
                self.assertRaises(ValueError),
            ):
                published_ports((specification,))


if __name__ == "__main__":
    unittest.main()
