"""Real Linux TUN in the owned VM's client namespace; no packet emulator."""

import ctypes
import fcntl
import json
import os
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path

TUNSETIFF = 0x400454CA
TUNGETIFF = 0x800454D2
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
CLONE_NEWNET = 0x40000000


def command(*argv):
    try:
        subprocess.run(argv, check=True, capture_output=True, timeout=15)
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace")[-1000:]
        raise RuntimeError(f"isolated TUN setup {argv[0]} failed: {detail}") from error


class RealTun:
    def __init__(self):
        self.name = "benchmark-client"
        self.device = "tun0"
        self.fd = None
        self._nat_comment = "benchmark-tun-" + uuid.uuid4().hex
        self._nat_rules = []
        self.record = {"kind": "linux-real-tun", "cleanup": False, "mtu": 1500}

    def __enter__(self):
        if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
            raise RuntimeError("real TUN setup requires the owned Linux guest")
        if not os.path.exists("/dev/net/tun"):
            os.makedirs("/dev/net", exist_ok=True)
            os.mknod("/dev/net/tun", 0o20600, os.makedev(10, 200))
        normal = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        try:
            command("ip", "netns", "add", self.name)
            command(
                "ip",
                "link",
                "add",
                "control-host",
                "type",
                "veth",
                "peer",
                "name",
                "control-client",
            )
            command("ip", "link", "set", "control-client", "netns", self.name)
            command("ip", "addr", "add", "10.255.254.1/30", "dev", "control-host")
            command(
                "ip",
                "-6",
                "addr",
                "add",
                "fd00:7663:1::1/64",
                "dev",
                "control-host",
                "nodad",
            )
            command("ip", "link", "set", "control-host", "up")
            client = os.open("/run/netns/" + self.name, os.O_RDONLY | os.O_CLOEXEC)
            try:
                self._setns(client)
                self.fd = os.open(
                    "/dev/net/tun", os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK
                )
                self._configure_flags()
            finally:
                self._setns(normal)
                os.close(client)
            self._client("link", "set", "lo", "up")
            self._client("addr", "add", "10.255.254.2/30", "dev", "control-client")
            self._client(
                "-6",
                "addr",
                "add",
                "fd00:7663:1::2/64",
                "dev",
                "control-client",
                "nodad",
            )
            self._client("link", "set", "control-client", "up")
            self._configure_device()
            for family, gateway in (("-4", "10.255.254.1"), ("-6", "fd00:7663:1::1")):
                self._client(
                    family,
                    "route",
                    "add",
                    "table",
                    "100",
                    "default",
                    "via",
                    gateway,
                    "dev",
                    "control-client",
                )
                self._client(
                    family,
                    "rule",
                    "add",
                    "priority",
                    "100",
                    "ipproto",
                    "tcp",
                    "dport",
                    "24003",
                    "lookup",
                    "100",
                )
            # OCI masks /proc/sys read-only. This remount is confined to this
            # owned VM, whose NET_ADMIN/SYS_ADMIN capabilities were explicit.
            command("mount", "-o", "remount,rw", "/proc/sys")
            command(
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
                "net.ipv6.conf.all.forwarding=1",
            )
            for binary, subnet in (
                ("iptables", "10.255.254.0/30"),
                ("ip6tables", "fd00:7663:1::/64"),
            ):
                rule = (
                    "-s",
                    subnet,
                    "-o",
                    "eth0",
                    "-m",
                    "comment",
                    "--comment",
                    self._nat_comment,
                    "-j",
                    "MASQUERADE",
                )
                command(binary, "-t", "nat", "-A", "POSTROUTING", *rule)
                self._nat_rules.append((binary, rule))
            self._wait_ipv6_ready()
            return self
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                error.add_note("owned TUN cleanup failed: " + repr(cleanup))
            raise
        finally:
            os.close(normal)

    @staticmethod
    def _setns(fd):
        library = ctypes.CDLL(None, use_errno=True)
        if library.setns(fd, CLONE_NEWNET):
            raise OSError(
                ctypes.get_errno(), "owned guest network namespace switch failed"
            )

    def _client(self, *argv):
        command("ip", "-n", self.name, *argv)

    def _wait_ipv6_ready(self):
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("owned IPv6 duplicate address detection timed out")
            rows = json.loads(
                subprocess.check_output(
                    ["ip", "-n", self.name, "-j", "-6", "addr", "show"],
                    text=True,
                    timeout=remaining,
                )
            )
            addresses = {
                row["ifname"]: row.get("addr_info")
                for row in rows
                if row.get("ifname") in ("control-client", self.device)
            }
            if any(not addresses.get(name) for name in ("control-client", self.device)):
                raise RuntimeError("owned IPv6 address observation unavailable")
            pending = False
            for values in addresses.values():
                for address in values:
                    if address.get("dadfailed"):
                        raise RuntimeError(
                            "owned IPv6 duplicate address detection failed"
                        )
                    pending |= bool(address.get("tentative"))
            if not pending:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("owned IPv6 duplicate address detection timed out")
            time.sleep(min(0.05, remaining))

    def _configure_device(self):
        """Route the shared raw-IP TUN inside the client namespace."""
        self._client("addr", "replace", "198.18.0.2/15", "dev", "tun0")
        self._client(
            "-6", "addr", "replace", "fd00:7663:2::2/64", "dev", "tun0", "nodad"
        )
        self._client("link", "set", "tun0", "mtu", "1500", "up")
        self._client("route", "replace", "default", "dev", "tun0")
        self._client("-6", "route", "replace", "default", "dev", "tun0")
        self._record_link()
        self.record_host_state()

    def _configure_flags(self):
        # One raw-IP queue, without virtio headers or framing extensions.
        requested = IFF_TUN | IFF_NO_PI
        fcntl.ioctl(self.fd, TUNSETIFF, struct.pack("16sH22x", b"tun0", requested))
        observed = fcntl.ioctl(self.fd, TUNGETIFF, bytes(40))
        actual = struct.unpack_from("H", observed, 16)[0]
        required = IFF_TUN | IFF_NO_PI
        forbidden = 0x0002 | 0x0010 | 0x0020 | 0x0100 | 0x4000
        if actual & required != required or actual & forbidden:
            raise RuntimeError("owned TUN effective flags differ from request")
        self.record.update(
            iff_flags_requested=requested,
            iff_flags_actual=actual,
        )

    def record_host_state(self):
        """Observe shared fd/profile without writing them during the session."""
        self.record["fd_status_flags"] = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        self.record["fd_descriptor_flags"] = fcntl.fcntl(self.fd, fcntl.F_GETFD)
        observed = fcntl.ioctl(self.fd, TUNGETIFF, bytes(40))
        self.record["iff_flags_actual"] = struct.unpack_from("H", observed, 16)[0]
        row = self._link_info()
        if type(row.get("mtu")) is not int or row["mtu"] != 1500:
            raise RuntimeError("owned TUN actual MTU differs from 1500")
        self._record_link(row)
        if "queue_length_requested" in self.record:
            self.record["eth0_tx_queue_len"] = self._link_info(host=True)["txqlen"]
        self.record["observed_mtu"] = row["mtu"]
        return dict(self.record)

    def configure_queue_lengths(self, length):
        """Apply and verify one shared queue profile before starting the core."""
        if type(length) is not int or length <= 0:
            raise ValueError("owned queue length must be a positive integer")
        self._client("link", "set", "dev", self.device, "txqueuelen", str(length))
        command("ip", "link", "set", "dev", "eth0", "txqueuelen", str(length))
        tun_row = self._link_info()
        eth0_row = self._link_info(host=True)
        if tun_row["txqlen"] != length or eth0_row["txqlen"] != length:
            raise RuntimeError("owned TUN/eth0 queue lengths differ from request")
        self._record_link(tun_row)
        self.record["eth0_tx_queue_len"] = eth0_row["txqlen"]
        self.record["queue_length_requested"] = length

    def _link_info(self, *, host=False):
        device = "eth0" if host else self.device
        argv = ["ip"] if host else ["ip", "-n", self.name]
        rows = json.loads(
            subprocess.check_output(
                [*argv, "-j", "link", "show", "dev", device],
                text=True,
                timeout=15,
            )
        )
        if not isinstance(rows, list) or len(rows) != 1:
            raise RuntimeError(f"owned {device} link metadata unavailable")
        row = rows[0]
        if not isinstance(row, dict) or type(row.get("txqlen")) is not int:
            raise RuntimeError(f"owned {device} queue length unavailable")
        if row["txqlen"] <= 0:
            raise RuntimeError(f"owned {device} queue length invalid")
        return row

    def _record_link(self, row=None):
        # Observe the actual queue length and qdisc without changing either.
        if row is None:
            row = self._link_info()
        self.record["tx_queue_len"] = row["txqlen"]
        kind = row.get("qdisc")
        self.record["qdisc"] = (
            kind
            if kind
            in ("noqueue", "pfifo_fast", "fq_codel", "fq", "pfifo", "bfifo", "mq")
            else "unknown"
        )

    def reject(self, host):
        # TCP REJECT must produce EOF/reset/refusal. Silence/timeout is not proof.
        script = (
            "import errno,socket,sys; "
            "s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] "
            "else socket.AF_INET); "
            "s.settimeout(5); "
            "\ntry:\n s.connect((sys.argv[1],443)); s.sendall(b'reject-witness'); "
            "assert s.recv(1)==b'', 'rejection returned payload'"
            "\nexcept OSError as e:\n assert e.errno in "
            "(errno.ECONNREFUSED,errno.ECONNRESET,errno.EPIPE,errno.ENOTCONN)"
            "\nfinally:\n s.close()"
        )
        command("ip", "netns", "exec", self.name, "python3", "-c", script, host)

    def close(self):
        self.record["cleanup"] = False
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if Path("/run/netns", self.name).exists():
            command("ip", "netns", "delete", self.name)
        if Path("/run/netns", self.name).exists():
            raise RuntimeError("owned guest network namespace remains after cleanup")
        existing = subprocess.run(
            ["ip", "link", "show", "control-host"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if existing.returncode == 0:
            command("ip", "link", "delete", "control-host")
        elif existing.returncode != 1:
            raise RuntimeError("owned guest control link cleanup check failed")
        remaining = subprocess.run(
            ["ip", "link", "show", "control-host"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if remaining.returncode != 1:
            raise RuntimeError("owned guest control link remains after cleanup")
        while self._nat_rules:
            binary, rule = self._nat_rules[-1]
            command(binary, "-t", "nat", "-D", "POSTROUTING", *rule)
            self._nat_rules.pop()
        self.record["cleanup"] = True

    def __exit__(self, _kind, error, _traceback):
        try:
            self.close()
        except BaseException as cleanup:
            if error is None:
                raise
            error.add_note("owned TUN cleanup failed: " + repr(cleanup))
