import os
import plistlib
import socket
import struct
import threading
import unittest
from unittest import mock

from tests import FakeJob, reset_data
from sideloop import remote, store

PHONE = "00008101-000A1234ABCD001E"
OTHER = "00008101-000B1234ABCD001E"
THIRD = "00008101-000C1234ABCD001E"


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


class FakeMux:
    """A usbmuxd-protocol server that records what it is sent and answers AddDevice like netmuxd."""

    def __init__(self, add_result=1):
        self.messages, self.add_result, self.stopped = [], add_result, False
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.sock.settimeout(0.1)
        self.addr = f"127.0.0.1:{self.sock.getsockname()[1]}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stopped:
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with c:
                c.settimeout(5)
                length, _, _, tag = struct.unpack("<IIII", _recv_exact(c, 16))
                msg = plistlib.loads(_recv_exact(c, length - 16))
                self.messages.append(msg)
                if msg["MessageType"] == "AddDevice" and self.add_result is not None:
                    body = plistlib.dumps({"Result": self.add_result})
                    c.sendall(struct.pack("<IIII", 16 + len(body), 1, 8, tag) + body)

    def types(self):
        return [m["MessageType"] for m in self.messages]

    def close(self):
        self.stopped = True
        self.sock.close()


class ValidIp(unittest.TestCase):
    def test_valid_ip_accepts_and_normalises(self):
        self.assertEqual(remote.valid_ip("10.8.0.2"), "10.8.0.2")
        self.assertEqual(remote.valid_ip("  10.8.0.2 "), "10.8.0.2")
        self.assertEqual(remote.valid_ip("FD00::0002"), "fd00::2")

    def test_valid_ip_empty_clears(self):
        for blank in ("", "   ", None):
            self.assertEqual(remote.valid_ip(blank), "")

    def test_valid_ip_rejects_garbage(self):
        for bad in ("10.8.0", "phone.lan", "10.8.0.2:62078", "10.8.0.2\nAPPLE_ID=x", "10.8.0.0/24"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                remote.valid_ip(bad)


class Reachable(unittest.TestCase):
    def test_listening_port_is_reachable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen()
            self.assertTrue(remote.reachable("127.0.0.1", s.getsockname()[1]))

    def test_closed_port_is_not_reachable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertFalse(remote.reachable("127.0.0.1", port))


class Session(unittest.TestCase):
    def setUp(self):
        self.mux = FakeMux()
        self.addCleanup(self.mux.close)

    def test_session_adds_then_removes_the_device(self):
        with remote.session(PHONE, "10.8.0.2", self.mux.addr) as env:
            self.assertEqual(self.mux.types(), ["RemoveDevice", "AddDevice"])
            self.assertEqual(env["USBMUXD_SOCKET_ADDRESS"], self.mux.addr)
            self.assertEqual(env["PATH"], os.environ["PATH"])
        self.assertEqual(self.mux.types(), ["RemoveDevice", "AddDevice", "RemoveDevice"])
        add = self.mux.messages[1]
        self.assertEqual((add["DeviceID"], add["IPAddress"], add["ConnectionType"]), (PHONE, "10.8.0.2", "Network"))
        self.assertEqual(add["ServiceName"], "_apple-mobdev2._tcp.local")

    def test_session_removes_the_device_when_the_run_fails(self):
        with self.assertRaises(KeyError), remote.session(PHONE, "10.8.0.2", self.mux.addr):
            raise KeyError
        self.assertEqual(self.mux.types()[-1], "RemoveDevice")

    def test_refused_add_raises_tunnel_error(self):
        self.mux.add_result = None
        with self.assertRaises(remote.TunnelError), remote.session(PHONE, "10.8.0.2", self.mux.addr):
            self.fail("the block must not run")

    def test_muxer_down_raises_tunnel_error(self):
        self.mux.close()
        with self.assertRaises(remote.TunnelError), remote.session(PHONE, "10.8.0.2", self.mux.addr):
            self.fail("the block must not run")


class RunDevices(unittest.TestCase):
    def setUp(self):
        reset_data()
        for udid in (PHONE, OTHER, THIRD):
            store.add_device(udid, f"iPhone {udid[-6:]}")
        store.set_device_tunnel_ip(PHONE, "10.8.0.2")
        self.mux = FakeMux()
        self.addCleanup(self.mux.close)
        patcher = mock.patch.object(remote, "TUNNEL_MUX", self.mux.addr)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.job, self.calls, self.codes = FakeJob(), [], []

    def runner(self, job, argv, env):
        self.calls.append((argv, env))
        return self.codes.pop(0) if self.codes else 0

    def run_devices(self, udids, local=False, reachable=True):
        with mock.patch.object(remote, "reachable", return_value=reachable) as probe:
            rc = remote.run_devices(self.job, udids, ["refresh.sh"], self.runner, lambda u: local)
        return rc, probe

    def test_local_device_takes_the_normal_path(self):
        rc, probe = self.run_devices([PHONE], local=True)
        self.assertEqual(self.calls, [(["refresh.sh", "--device", PHONE], None)])
        probe.assert_not_called()
        self.assertEqual(self.mux.messages, [])

    def test_away_device_goes_through_the_tunnel(self):
        self.run_devices([PHONE])
        (argv, env), = self.calls
        self.assertEqual(argv, ["refresh.sh", "--device", PHONE])
        self.assertEqual(env["USBMUXD_SOCKET_ADDRESS"], self.mux.addr)
        self.assertEqual(self.mux.types(), ["RemoveDevice", "AddDevice", "RemoveDevice"])
        self.assertTrue(any("10.8.0.2" in line for line in self.job.lines))

    def test_unreachable_device_takes_the_normal_path(self):
        self.run_devices([PHONE], reachable=False)
        self.assertEqual(self.calls, [(["refresh.sh", "--device", PHONE], None)])
        self.assertEqual(self.mux.messages, [])

    def test_device_without_tunnel_ip_is_not_probed(self):
        rc, probe = self.run_devices([OTHER])
        self.assertEqual(self.calls, [(["refresh.sh", "--device", OTHER], None)])
        probe.assert_not_called()

    def test_tunnel_error_falls_back(self):
        self.mux.add_result = None
        rc, _ = self.run_devices([PHONE])
        self.assertEqual(self.calls, [(["refresh.sh", "--device", PHONE], None)])
        self.assertTrue(any(line.startswith("✗") for line in self.job.lines))

    def test_first_failure_code_is_returned(self):
        self.codes = [0, 3, 5]
        rc, _ = self.run_devices([PHONE, OTHER, THIRD], local=True)
        self.assertEqual(rc, 3)
        self.assertEqual(len(self.calls), 3)

    def test_cancel_stops_loop(self):
        def cancelling(job, argv, env):
            job.cancelled = True
            return self.runner(job, argv, env)
        remote.run_devices(self.job, [PHONE, OTHER], ["refresh.sh"], cancelling, lambda u: True)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
