"""Bounded conditional rule resource in the already owned HTTP origin."""

from __future__ import annotations

import json
import threading

from .mihomo_lab import save

AUTHORIZATION = "Bearer synthetic-provider"
PATH = "/rewrite-provider"


class ProviderService:
    def __init__(self, root, consumer):
        self.root, self.consumer = root, consumer
        self.lock, self.receipts = threading.Lock(), []

    def _publish(self):
        temporary = self.root / "http-provider-receipts.tmp"
        save(temporary, self.receipts)
        temporary.replace(self.root / "http-provider-receipts.json")

    def serve(self, wire, path, headers, source):
        if path != PATH:
            return False
        authenticated = (
            source == self.consumer and headers.get("authorization") == AUTHORIZATION
        )
        state = json.loads((self.root / "remote-provider-state.json").read_text())
        body = state["body"].encode()
        if len(body) > 65536:
            raise ValueError("provider response exceeded fixture bound")
        conditional = headers.get("if-none-match") == state["etag"]
        status = 403 if not authenticated else 304 if conditional else 200
        output = body if status == 200 else b""
        fields = f"ETag: {state['etag']}\r\nConnection: close\r\n"
        if status != 304:
            fields += f"Content-Length: {len(output)}\r\n"
        receipt = {
            "status": status,
            "authenticated": authenticated,
            "conditional": conditional,
            "body_bytes": len(output),
            "etag": state["etag"],
        }
        with self.lock:
            if len(self.receipts) >= 64:
                raise ValueError("provider request count exceeded fixture bound")
            self.receipts.append(receipt)
            self._publish()
        header = f"HTTP/1.1 {status} Fixture\r\n{fields}\r\n".encode()
        if status == 200 and state.get("pause"):
            # A valid declared body remains unfinished until Core cancels its
            # resource download. The source independently observes socket EOF;
            # a fixture timeout never counts as successful cancellation.
            wire.sendall(header + output[:1])
            with self.lock:
                receipt["transfer"] = "paused"
                self._publish()
            wire.settimeout(3)
            try:
                if wire.recv(1):
                    raise ValueError("paused provider received unexpected extra data")
                outcome = "cancelled"
            except ConnectionError:
                outcome = "cancelled"
            except TimeoutError:
                outcome = "timed-out"
            with self.lock:
                receipt["transfer"] = outcome
                self._publish()
        else:
            wire.sendall(header + output)
        return True


def state(root, generation, *, invalid=False, pause=False):
    payload = {
        "payload": [
            {
                "url": "https://a.test:25882/remote-generation",
                "match": "exact",
                "action": "replace",
                "replacement": "https://b.test:25882/" + generation,
            }
        ]
    }
    temporary = root / "remote-provider-state.tmp"
    save(
        temporary,
        {
            "etag": '"' + generation + '"',
            "body": "payload: invalid" if invalid else json.dumps(payload),
            "pause": pause,
        },
    )
    temporary.replace(root / "remote-provider-state.json")


def declarations(peer):
    return {
        "remote": {
            "type": "http",
            "url": f"http://{peer}:25880{PATH}",
            "path": "rewrite-cache/remote.json",
            "interval": 0,
            "header": {"Authorization": [AUTHORIZATION]},
        },
        "unreferenced": {
            "type": "http",
            "url": f"http://{peer}:25880/never-load",
            "interval": 0,
        },
    }
