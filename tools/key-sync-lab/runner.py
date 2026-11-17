"""Two-namespace kernel TUN acceptance. Lab-only file queue, no Docker socket.

Client commands are a fixed allowlist; request/results never contain key bytes.
The private volume is deleted with this Compose project's down --volumes.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

STATE = Path("/lab")


def write(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data))
    temporary.chmod(0o600)
    temporary.replace(path)


def client():
    active = None
    (STATE / "ready").touch(mode=0o600)
    try:
        while True:
            for path in sorted(STATE.glob("request-*.json")):
                request = json.loads(path.read_text())
                config = Path(request.get("config", "/lab/unused"))
                if not config.is_relative_to(STATE) or ".." in config.parts:
                    raise ValueError("invalid lab config path")
                action = request["action"]
                if action == "handshake":
                    result = subprocess.run(["bproto", "--config", str(config), "connect", "--seconds", "1"],
                        capture_output=True, timeout=8)
                    value = dict(ok=result.returncode == 0,
                        handshake_failure=b"handshake" in (result.stdout + result.stderr).lower())
                elif action == "up":
                    if active is not None:
                        raise ValueError("lab tunnel already running")
                    active = subprocess.Popen(["bproto", "--config", str(config), "up", "--iface", "bpclient", "--no-default-route"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        if active.poll() is not None:
                            raise RuntimeError("client TUN process exited")
                        if subprocess.run(["ip", "link", "show", "bpclient"], capture_output=True).returncode == 0:
                            break
                        time.sleep(.05)
                    value = dict(ok=subprocess.run(["ip", "link", "show", "bpclient"], capture_output=True).returncode == 0)
                elif action == "ping":
                    # Explicit source interface prevents a bypass through eth0.
                    result = subprocess.run(["ping", "-n", "-I", "bpclient", "-c", "2", "-W", "1", "10.66.0.1"],
                        capture_output=True, timeout=5)
                    value = dict(ok=result.returncode == 0)
                elif action == "stop":
                    if active is not None and active.poll() is None:
                        active.terminate()
                        active.wait(timeout=5)
                    active = None
                    value = dict(ok=True)
                else:
                    raise ValueError("unknown lab action")
                write(STATE / path.name.replace("request-", "response-"), value)
                path.unlink()
            time.sleep(.03)
    finally:
        if active is not None and active.poll() is None:
            active.terminate()
            active.wait(timeout=5)


def server():
    os.environ.update(BPROTO_TEST_STATE_ROOT="/lab", BPROTO_TEST_DATAPATH="1",
        BPROTO_TEST_SERVER_ADDRESS=f'{socket.gethostbyname("server")}:4443')
    spec = importlib.util.spec_from_file_location("sync_fixture", "/app/tests/test_key_sync_e2e.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)

    class DatapathCase(fixture.KeySyncE2E):
        sequence = 0

        def remote(self, action, config="/lab/unused"):
            self.sequence += 1
            name = f"request-{self.sequence:04d}.json"
            response = STATE / name.replace("request-", "response-")
            write(STATE / name, dict(action=action, config=str(config)))
            self.wait(response.exists, timeout=15)
            result = json.loads(response.read_text())
            response.unlink()
            return result

        def handshake(self, path, succeeds):
            result = self.remote("handshake", path)
            self.assertEqual(result["ok"], succeeds)
            if not succeeds:
                self.assertTrue(result["handshake_failure"])

        def test_create_apply_handshake_revoke_rejects_handshake(self):
            self.wait(lambda: (STATE / "ready").exists())
            record = self.api("POST", f"/api/inbounds/{self.inbound}/clients", dict(username="tun-device", label="lab"))
            path, psk = self.client_config(record)
            self.wait(self.applied)
            self.handshake(path, True)
            self.assertTrue(self.remote("up", path)["ok"])
            try:
                self.assertTrue(self.remote("ping")["ok"], "No kernel TUN packet round-trip")
                self.api("POST", f'/api/keys/{record["key_id"]}/revoke')
                self.wait(self.applied)
                self.assertNotIn(psk, self.config.read_text())
                self.assertFalse(self.remote("ping")["ok"], "Revoked live tunnel still carries packets")
                self.handshake(path, False)
                self.assertIsNone(self.native.poll())
            finally:
                self.remote("stop")

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DatapathCase))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["client"]:
        client()
    elif sys.argv[1:] == ["server"]:
        raise SystemExit(server())
    else:
        raise SystemExit("expected isolated lab role")
