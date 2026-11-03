"""Native response ownership checks; business evidence requires an owned guest."""

import ctypes
import json
import unittest
from unittest.mock import Mock, patch

from container_benchmark.interop import protocol_integration as integration


class InvokeOwnershipTests(unittest.TestCase):
    def invoke(self, raw):
        buffer = ctypes.create_string_buffer(raw)
        library = Mock()
        library.VoleInvoke.return_value = ctypes.addressof(buffer)
        with patch.object(integration.ctypes, "CDLL", return_value=library):
            invoke = integration.Invoke("/unused/libvole.so")
        return buffer, library, invoke

    def test_native_response_is_freed_before_success_is_returned(self):
        buffer, library, invoke = self.invoke(
            b'{"success":true,"data":{"state":"stopped"}}'
        )
        self.assertEqual(invoke.call("getState", instance="7"), {"state": "stopped"})
        request = json.loads(library.VoleInvoke.call_args.args[0])
        self.assertEqual(
            request, {"method": "getState", "instanceId": "7", "payload": {}}
        )
        library.VoleFree.assert_called_once_with(ctypes.addressof(buffer))

    def test_failed_and_malformed_responses_still_return_the_native_allocation(self):
        for raw, error in (
            (b'{"success":false,"error":"private config"}', RuntimeError),
            (b"invalid-json", ValueError),
        ):
            with self.subTest(raw=raw):
                buffer, library, invoke = self.invoke(raw)
                with self.assertRaises(error) as raised:
                    invoke.call("version")
                self.assertNotIn("private config", str(raised.exception))
                library.VoleFree.assert_called_once_with(ctypes.addressof(buffer))


if __name__ == "__main__":
    unittest.main()
