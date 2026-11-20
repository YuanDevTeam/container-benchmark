# Mac full workload origin

This Go fixture runs in the owned Linux origin guests. Build it in the prepared
image. Pass a frozen per-branch manifest with `-manifest` and set
`BENCHMARK_ISOLATED=1`. Use `go test ./...` for offline fixture verification.

## Manifest

```json
{
  "schema_version": 1,
  "run_id": "11111111111111111111111111111111",
  "control_token": "2222222222222222222222222222222222222222222222222222222222222222",
  "bind_ip": "0.0.0.0",
  "ports": {"control": 28000, "http1": 28001, "tls_h1": 28002, "tls_h2": 28003},
  "udp_base_port": 29000,
  "udp_destinations": 64,
  "tls_cert_file": "/run/benchmark/inputs/tls/origin-leaf.pem",
  "tls_key_file": "/run/benchmark/inputs/tls/origin-leaf.key",
  "guest_root": "/run/benchmark/inputs",
  "window_limit": 64,
  "prepare_route_hold_ms": 250,
  "allowed_branch": "hit",
  "output_dir": "/run/benchmark/origin-hit-result",
  "ready_file": "/run/benchmark/origin-ready-hit.json"
}
```

Each branch uses distinct addresses and equivalent ports. The workload uses one
or 64 UDP destinations independently of the proxy's 50-port budget. TLS inputs
stay inside `guest_root`. Optional ready and result paths stay under owned
`/run/benchmark/` paths outside frozen inputs.

## Window protocol

The bearer-authenticated control endpoint exposes `GET /v1/clock`,
`POST /v1/windows/start` and each window's `barrier`, `stats` and `seal`.
Schedule start using the midpoint of bounded clock exchanges. The origin uses
its monotonic timeline for the active and drain intervals. A seal is immutable
and requires the full drain. SIGTERM and SIGINT close listeners and join
workers. Shutdown before seal records an aborted receipt.

Plain HTTP uses H1. Separate TLS listeners enforce H1 or H2 via ALPN. HTTP
posts validate the complete body and rewrite stage. Completion receipts and
active/drain byte counts are recorded separately. The UDP handshake binds
each logical flow to its source at each target port. Payload, credentials and
raw endpoints are excluded from the bounded receipt. Its wire layouts and
field definitions are in `http.go`, `udp.go` and `ledger.go`.

See [full Mac pressure](../../docs/mac-full-pressure.md) for configuration and
acceptance rules.
