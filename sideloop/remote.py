import ipaddress
import os
import socket
import subprocess
from contextlib import contextmanager

from . import store
from .config import TUNNEL_MUX, WG_GATEWAY, WG_SUBNET
from .lockdown import LOCKDOWN_PORT, mux_connect, mux_request, mux_send
from .log import log

# Reaches a device that is away from home through a WireGuard tunnel. Bonjour doesn't cross the
# tunnel, so the device is handed to a second netmuxd by its tunnel IP for the length of one run.
# That netmuxd runs without heartbeat, so nothing talks to the phone outside a run.
PROBE_TIMEOUT = 3
SERVICE_NAME = "_apple-mobdev2._tcp.local"


class TunnelError(Exception):
    pass


def add_route():
    if not (WG_SUBNET and WG_GATEWAY):
        return
    r = subprocess.run(["ip", "route", "replace", WG_SUBNET, "via", WG_GATEWAY], capture_output=True, text=True)
    if r.returncode:
        log(f"couldn't route {WG_SUBNET} via {WG_GATEWAY}: {r.stderr.strip() or r.returncode}")
    else:
        log(f"routing {WG_SUBNET} via {WG_GATEWAY} to reach devices away from home")


def valid_ip(text):
    text = str(text or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError("enter the device's WireGuard IP, like 10.8.0.2") from None


def reachable(ip, port=LOCKDOWN_PORT):
    try:
        socket.create_connection((ip, port), timeout=PROBE_TIMEOUT).close()
        return True
    except OSError:
        return False


def _remove(udid, mux):
    try:
        with mux_connect(mux) as s:
            mux_send(s, {"MessageType": "RemoveDevice", "DeviceID": udid})
            s.recv(1)  # netmuxd closes the connection once it has queued the removal
    except OSError:
        pass


@contextmanager
def session(udid, ip, mux=None):
    """Lists the device on the tunnel muxer at ip while the block runs and yields the environment
    that points libimobiledevice and AltServer at that muxer."""
    mux = mux or TUNNEL_MUX
    _remove(udid, mux)
    try:
        with mux_connect(mux) as s:
            r = mux_request(s, {"MessageType": "AddDevice", "ConnectionType": "Network",
                                "ServiceName": SERVICE_NAME, "IPAddress": ip, "DeviceID": udid})
    except OSError as e:
        raise TunnelError(f"the tunnel muxer didn't take {store.device_name(udid)} ({e}); is it paired?") from None
    if r.get("Result") != 1:
        raise TunnelError(f"the tunnel muxer refused {store.device_name(udid)} ({r})")
    try:
        yield dict(os.environ, USBMUXD_SOCKET_ADDRESS=mux)
    finally:
        _remove(udid, mux)


def run_devices(job, udids, argv, runner, is_local):
    """Runs `argv --device <udid>` for each device through runner(job, argv, env) and returns the
    first non-zero exit code. A device that isn't on USB or this Wi-Fi but answers on its WireGuard
    IP is reached through the tunnel; every other device runs exactly as before."""
    rc = 0
    for udid in udids:
        if job.cancelled:
            break
        cmd = [*argv, "--device", udid]
        ip = store.device_tunnel_ip(udid)
        result = None
        if ip and not is_local(udid) and reachable(ip):
            job.say(f"{store.device_name(udid)} is away from home; reaching it over WireGuard at {ip}")
            log(f"reaching {store.device_name(udid)} over WireGuard at {ip}")
            try:
                with session(udid, ip) as env:
                    result = runner(job, cmd, env)
            except TunnelError as e:
                job.say(f"✗ {e}")
        if result is None:
            result = runner(job, cmd, None)
        rc = rc or result
    return rc
